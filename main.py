"""
Arbex Shadow Webhook Receiver
------------------------------
Принимает lifecycle-события от Arbex PriceArb Feed.
Shadow-режим: только приём и логирование, без торговых ордеров.

Архитектура хранения:
  Railway filesystem — ephemeral (стирается при деплое).
  Все события пишутся в stdout как JSON-строки.
  Railway автоматически собирает stdout в персистентные логи.
  Для долгосрочного хранения — добавить Railway Postgres / S3 в будущем.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone

from collections import deque

from collections import deque

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse


def _relay_to_paper(payload: dict) -> None:
    """Перенаправляет событие в arbex-paper /webhook."""
    import urllib.request
    import json
    
    paper_url = os.environ.get("ARBEX_PAPER_WEBHOOK_URL")
    if not paper_url:
        return
    
    secret = os.environ.get("ARBEX_WEBHOOK_SECRET", "")
    body = json.dumps(payload).encode("utf-8")
    
    try:
        req = urllib.request.Request(
            f"https://{paper_url}/webhook",
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Arbex-Webhook-Secret": secret,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
        print(f"[RELAY] → paper status={status} opp={payload.get("opportunity_id","?")[:30]}", flush=True)
    except Exception as e:
        print(f"[RELAY ERROR] {e}", flush=True)


# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

# Поддерживаем оба имени переменной для плавной миграции.
# Приоритет: ARBEX_WEBHOOK_SECRET > ARBEX_WEBHOOK_TOKEN
_SECRET_RAW = os.environ.get("ARBEX_WEBHOOK_SECRET") or os.environ.get("ARBEX_WEBHOOK_TOKEN") or ""
SECRET: bytes = _SECRET_RAW.encode()

MAX_BODY_BYTES = 512 * 1024  # 512 KB

# Кольцевой буфер — последние 500 событий в памяти
# Сбрасывается при редеплое, для shadow-режима достаточно
EVENTS_BUFFER: deque = deque(maxlen=500)

# ---------------------------------------------------------------------------
# Логирование — структурированный JSON в stdout
# Каждая строка = один JSON-объект; Railway Logs их индексирует.
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",  # только сам текст — JSON будем формировать вручную
)
logger = logging.getLogger("arbex_webhook")


def _log(level: str, event: str, **fields) -> None:
    """Пишет одну JSON-строку в stdout."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        **fields,
    }
    # print гарантирует flush в stdout; logger.info добавил бы лишний prefix
    print(json.dumps(record, ensure_ascii=False, default=str), flush=True)


# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------

# docs/redoc отключены: раскрывают схему заголовков, включая имя секрета
app = FastAPI(
    title="Arbex Shadow Webhook",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_log("INFO", "startup", secret_configured=bool(SECRET))


# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9_\-]")


def _safe_id(value: object, max_len: int = 64) -> str:
    """Санитизирует произвольное значение для использования в логах/именах."""
    if not isinstance(value, str):
        return "unknown"
    cleaned = _SAFE_ID_RE.sub("_", value)[:max_len]
    return cleaned or "unknown"


def _check_secret(provided: str | None) -> bool:
    """Constant-time сравнение через hmac.compare_digest (защита от timing attack)."""
    if not provided:
        return False
    try:
        return hmac.compare_digest(provided.encode(), SECRET)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Эндпоинты
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "arbex-shadow-webhook"}


@app.post("/webhook")
async def webhook(
    request: Request,
    x_arbex_webhook_secret: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    received_utc_ms = int(time.time() * 1000)
    request_id = str(uuid.uuid4())

    # -- 1. Проверка конфигурации --
    if not SECRET:
        _log("ERROR", "webhook.misconfigured", request_id=request_id)
        raise HTTPException(status_code=503, detail="Service unavailable")

    # -- 2. Аутентификация --
    # Принимаем X-Arbex-Webhook-Secret (стандарт Arbex) или Bearer-токен (legacy).
    bearer_value = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer_value = authorization[7:]

    auth_ok = _check_secret(x_arbex_webhook_secret) or _check_secret(bearer_value)
    if not auth_ok:
        _log("WARN", "webhook.auth_failed", request_id=request_id,
             remote=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=401, detail="Unauthorized")

    # -- 3. Ограничение размера тела --
    raw_body = await request.body()
    if len(raw_body) > MAX_BODY_BYTES:
        _log("WARN", "webhook.payload_too_large", request_id=request_id,
             size=len(raw_body))
        raise HTTPException(status_code=413, detail="Payload too large")

    if not raw_body:
        raise HTTPException(status_code=400, detail="Empty body")

    # -- 4. Парсинг --
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        _log("WARN", "webhook.invalid_json", request_id=request_id, error=str(exc))
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not isinstance(payload, dict):
        _log("WARN", "webhook.not_object", request_id=request_id,
             got_type=type(payload).__name__)
        raise HTTPException(status_code=400, detail="JSON object expected")

    # -- 5. Логирование события в stdout (персистентно через Railway Logs) --
    # Секрет из заголовков намеренно исключён.
    safe_headers = {
        k: "[REDACTED]" if k.lower() in {"x-arbex-webhook-secret", "authorization"} else v
        for k, v in request.headers.items()
    }

    _log(
        "INFO",
        "webhook.received",
        request_id=request_id,
        received_utc_ms=received_utc_ms,
        opportunity_id=_safe_id(payload.get("opportunity_id")),
        event_type=payload.get("event_type"),
        sequence=payload.get("sequence"),
        schema_version=safe_headers.get("x-arbex-schema-version"),
        headers=safe_headers,
        payload=payload,
    )

    # Сохраняем в буфер для GET /events
    # Relay в paper-trader (если configured)
    _relay_to_paper(payload)
    
    EVENTS_BUFFER.append({
        "received_utc_ms": received_utc_ms,
        "request_id": request_id,
        "payload": payload,
    })

    return JSONResponse(
        status_code=200,
        content={"status": "accepted", "received_utc_ms": received_utc_ms, "request_id": request_id},
    )


@app.get("/events")
async def events(
    authorization: str | None = Header(default=None),
    limit: int = 50,
) -> JSONResponse:
    """
    Отдаёт последние события из буфера.
    Авторизация: Bearer <ARBEX_WEBHOOK_SECRET>
    Параметр: ?limit=N (макс 500, по умолчанию 50)
    """
    bearer_value = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer_value = authorization[7:]

    if not _check_secret(bearer_value):
        raise HTTPException(status_code=401, detail="Unauthorized")

    limit = max(1, min(limit, 500))
    items = list(EVENTS_BUFFER)[-limit:]

    return JSONResponse(content={
        "count": len(items),
        "total_buffered": len(EVENTS_BUFFER),
        "events": items,
    })

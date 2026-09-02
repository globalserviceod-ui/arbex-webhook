from fastapi import FastAPI, Request, Header, HTTPException
from datetime import datetime, timezone
import json
import os
import time

app = FastAPI()

TOKEN = os.environ.get("ARBEX_WEBHOOK_TOKEN", "")

os.makedirs("received", exist_ok=True)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "arbex-shadow-webhook"}


@app.post("/webhook")
async def webhook(
    request: Request,
    authorization: str | None = Header(default=None)
):
    if not TOKEN:
        raise HTTPException(status_code=500, detail="Token not configured")

    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")

    raw_body = await request.body()
    received_utc_ms = int(time.time() * 1000)

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    record = {
        "received_utc_ms": received_utc_ms,
        "received_utc": datetime.now(timezone.utc).isoformat(),
        "headers": dict(request.headers),
        "payload": payload,
    }

    filename = f"received/{received_utc_ms}_{payload.get('opportunity_id', 'unknown')}.json"
    with open(filename, "w") as f:
        json.dump(record, f, indent=2)

    print(
        f"[WEBHOOK] received={received_utc_ms} "
        f"opportunity_id={payload.get('opportunity_id')} "
        f"event_type={payload.get('event_type')}"
    )

    return {"status": "accepted", "received_utc_ms": received_utc_ms}

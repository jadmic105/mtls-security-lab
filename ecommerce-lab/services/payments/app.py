"""Payments service.

- /charge            called by orders (mTLS identity "orders"); charges via the PSP
- /webhooks/payment  PSP events, arriving through the edge (mTLS identity "edge");
                     authenticity is proven by an HMAC signature, not by the network path

Talks to the PSP over mTLS with a merchant certificate issued by the PSP's CA,
plus an API key read from the environment (a secrets manager in production).
"""
import hashlib
import hmac
import json
import os
import time

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

CERTS = os.environ["CERTS_DIR"]
PSP_URL = os.environ.get("PSP_URL", "https://127.0.0.1:9103")
PSP_API_KEY = os.environ["PSP_API_KEY"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()
WEBHOOK_TOLERANCE_SECONDS = 300

seen_event_ids: set[str] = set()  # use a database in production

app = FastAPI(title="Payments service")


class ChargeRequest(BaseModel):
    order_id: str
    amount_cents: int
    payment_token: str


@app.post("/charge")
def charge(body: ChargeRequest, x_client_cn: str = Header(default="")):
    if x_client_cn != "orders":
        raise HTTPException(status_code=403, detail="caller not allowed")

    resp = requests.post(
        f"{PSP_URL}/v1/charges",
        json={"amount_cents": body.amount_cents, "payment_token": body.payment_token},
        headers={
            "Authorization": f"Bearer {PSP_API_KEY}",
            "Idempotency-Key": body.order_id,
        },
        cert=(f"{CERTS}/merchant-payments.crt", f"{CERTS}/merchant-payments.key"),
        verify=f"{CERTS}/psp-ca.crt",
        timeout=10,
    )
    if resp.status_code == 402:
        raise HTTPException(status_code=402, detail="payment declined")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"PSP error ({resp.status_code})")
    result = resp.json()
    return {"charge_id": result["id"], "status": result["status"]}


def parse_signature(header: str) -> tuple[int, str]:
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    return int(parts["t"]), parts["v1"]


@app.post("/webhooks/payment")
async def payment_webhook(
    request: Request,
    x_client_cn: str = Header(default=""),
    x_signature: str = Header(default=""),
):
    if x_client_cn != "edge":
        raise HTTPException(status_code=403, detail="caller not allowed")

    raw = await request.body()
    try:
        timestamp, received = parse_signature(x_signature)
    except (KeyError, ValueError):
        raise HTTPException(status_code=401, detail="missing or malformed signature")

    if abs(time.time() - timestamp) > WEBHOOK_TOLERANCE_SECONDS:
        raise HTTPException(status_code=401, detail="stale timestamp")

    expected = hmac.new(WEBHOOK_SECRET, f"{timestamp}.".encode() + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received):
        raise HTTPException(status_code=401, detail="invalid signature")

    try:
        event = json.loads(raw)
        event_id = str(event["id"])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="invalid event body")

    if event_id in seen_event_ids:
        raise HTTPException(status_code=409, detail="duplicate event (replay)")
    seen_event_ids.add(event_id)

    return {"received": True, "event_id": event_id, "type": event.get("type")}

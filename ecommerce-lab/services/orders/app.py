"""Orders service: customer checkout.

Reached only through its nginx sidecar, which verifies the caller's mTLS
certificate and passes the verified identity in X-Client-CN.
Calls the payments service over mTLS with its own "orders" identity.
"""
import json
import os
import re
import uuid

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.concurrency import run_in_threadpool

CERTS = os.environ["CERTS_DIR"]
PAYMENTS_URL = os.environ.get("PAYMENTS_URL", "https://127.0.0.1:9102")
ALLOWED_CALLERS = {"edge"}

# 13-19 digits, optionally separated by spaces or dashes
PAN_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

app = FastAPI(title="Orders service")


def luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def contains_card_number(text: str) -> bool:
    return any(luhn_ok(m.group()) for m in PAN_CANDIDATE.finditer(text))


@app.get("/api/health")
def health(x_client_cn: str = Header(default="")):
    if x_client_cn not in ALLOWED_CALLERS:
        raise HTTPException(status_code=403, detail="caller not allowed")
    return {"service": "orders", "status": "ok"}


@app.post("/api/checkout")
async def checkout(request: Request, x_client_cn: str = Header(default="")):
    # Defense in depth: nginx already enforces this, the app checks again.
    if x_client_cn not in ALLOWED_CALLERS:
        raise HTTPException(status_code=403, detail="caller not allowed")

    raw = (await request.body()).decode("utf-8", errors="replace")

    # Card data must never reach our servers: the browser tokenizes it with the PSP.
    if contains_card_number(raw):
        raise HTTPException(
            status_code=400,
            detail="Raw card numbers are not accepted. Tokenize the card with the payment provider first.",
        )

    try:
        data = json.loads(raw)
        item = str(data["item"])
        amount = int(data["amount_cents"])
        token = str(data["payment_token"])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="expected item, amount_cents, payment_token")
    if amount <= 0 or not token.startswith("tok_"):
        raise HTTPException(status_code=400, detail="invalid amount or payment token")

    order_id = "ord_" + uuid.uuid4().hex[:12]

    resp = await run_in_threadpool(
        requests.post,
        f"{PAYMENTS_URL}/charge",
        json={"order_id": order_id, "amount_cents": amount, "payment_token": token},
        cert=(f"{CERTS}/orders.crt", f"{CERTS}/orders.key"),
        verify=f"{CERTS}/internal-ca.crt",
        timeout=10,
    )
    if resp.status_code == 402:
        raise HTTPException(status_code=402, detail="payment declined")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"payments service error ({resp.status_code})")

    charge = resp.json()
    return {"order_id": order_id, "item": item, "status": "paid", "charge": charge}

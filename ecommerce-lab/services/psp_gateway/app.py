"""Mock payment service provider (PSP) gateway.

Stands in for a real provider. Requires both:
  - mTLS with a merchant certificate issued by the PSP's own CA (checked by nginx)
  - a valid API key
"""
import hmac
import os
import uuid

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

API_KEY = os.environ["PSP_API_KEY"]
processed: dict[str, dict] = {}  # Idempotency-Key -> response

app = FastAPI(title="Mock PSP gateway")


class Charge(BaseModel):
    amount_cents: int
    payment_token: str


@app.post("/v1/charges")
def create_charge(
    body: Charge,
    authorization: str = Header(default=""),
    idempotency_key: str = Header(default=""),
    x_client_cn: str = Header(default=""),
):
    if x_client_cn != "merchant-payments":
        raise HTTPException(status_code=403, detail="unknown merchant")
    if not hmac.compare_digest(authorization.encode(), f"Bearer {API_KEY}".encode()):
        raise HTTPException(status_code=401, detail="invalid API key")
    if idempotency_key and idempotency_key in processed:
        return processed[idempotency_key]
    if not body.payment_token.startswith("tok_") or body.payment_token == "tok_declined":
        raise HTTPException(status_code=402, detail="card declined")

    result = {
        "id": "ch_" + uuid.uuid4().hex[:16],
        "status": "succeeded",
        "amount_cents": body.amount_cents,
    }
    if idempotency_key:
        processed[idempotency_key] = result
    return result

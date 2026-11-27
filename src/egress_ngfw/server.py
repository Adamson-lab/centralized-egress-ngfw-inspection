from datetime import datetime, timezone
import json
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
import httpx

from src.egress_ngfw.inspector import (
    CentralizedEgressInspector,
    EgressLeaseConflict,
    EgressLeaseManager,
    StaleInspectionToken,
    verify_egress_request,
)
from storage.audit_log import HashChainedAuditLog

app = FastAPI(title="centralized-egress-ngfw-inspection", version="0.1.0")

AUDIT_LOG = HashChainedAuditLog()
LEASE_MGR = EgressLeaseManager(audit_log=AUDIT_LOG, ttl_sec=25.0)


def _eval_opa(opa_url: str, opa_input: dict[str, Any]) -> tuple[bool, str]:
    base = opa_url.rstrip("/")
    with httpx.Client(timeout=3.0) as client:
        r1 = client.post(f"{base}/v1/data/egress/ngfw", json={"input": opa_input})
        r1.raise_for_status()
        d1 = r1.json().get("result") or {}
        if not d1.get("allow", False):
            return False, d1.get("reason", "denied by NGFW inspection policy")

        r2 = client.post(f"{base}/v1/data/egress/window", json={"input": opa_input})
        r2.raise_for_status()
        d2 = r2.json().get("result") or {}
        if not d2.get("allow", False):
            return False, d2.get("reason", "denied by change window policy")

        return True, d2.get("reason", "allowed")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    ok, msg = AUDIT_LOG.verify()
    return {
        "status": "ok" if ok else "degraded",
        "audit_status": msg,
        "utc_time": datetime.now(timezone.utc).isoformat(),
        "state": LEASE_MGR.snapshot(),
    }


@app.post("/v1/egress/inspect")
async def inspect_egress_flow(
    request: Request,
    x_signature_256: str | None = Header(default=None, alias="X-Signature-256"),
    x_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
) -> dict[str, Any]:
    raw_body = await request.body()
    secret = os.getenv("WEBHOOK_HMAC_SECRET", "local-dev-egress-ngfw-secret")
    valid, reason = verify_egress_request(secret, x_signature_256, x_timestamp, raw_body)
    if not valid:
        raise HTTPException(status_code=401, detail={"error": reason})

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "malformed json payload"})

    source_cidr = str(payload.get("source_cidr", "10.50.1.0/24"))
    destination_port = int(payload.get("destination_port", 443))
    protocol = str(payload.get("protocol", "tcp"))
    ngfw_profile = str(payload.get("ngfw_profile", "tls-inspect-strict"))
    holder_id = str(payload.get("holder_id", "ngfw-worker-1"))
    role = str(payload.get("operator_role", "sec-ngfw"))
    grace_lock = payload.get("grace_lock") or {}
    grace_mins = int(grace_lock.get("extra_minutes", 0)) if grace_lock.get("active") else 0
    now_utc = datetime.now(timezone.utc)

    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    try:
        allowed, policy_reason = _eval_opa(
            opa_url,
            {
                "source_cidr": source_cidr,
                "destination_port": destination_port,
                "protocol": protocol,
                "ngfw_profile": ngfw_profile,
                "operator_role": role,
                "utc_hour": now_utc.hour,
                "grace_lock": grace_lock,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"opa check failed: {exc}"})

    if not allowed:
        raise HTTPException(status_code=403, detail={"error": policy_reason})

    route_key = f"{source_cidr}/{protocol}/{destination_port}"
    try:
        lease = LEASE_MGR.acquire(
            route_key=route_key,
            holder_id=holder_id,
            now_utc=now_utc.timestamp(),
            grace_extension_sec=grace_mins * 60.0,
        )
    except EgressLeaseConflict as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})

    inspector = CentralizedEgressInspector(
        lease_manager=LEASE_MGR,
        region=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566"),
        bucket=os.getenv("EGRESS_AUDIT_BUCKET", "centralized-egress-ngfw-audit"),
    )
    try:
        res = inspector.inspect_and_route(
            source_cidr=source_cidr,
            destination_port=destination_port,
            protocol=protocol,
            ngfw_profile=ngfw_profile,
            fencing_token=lease.fencing_token,
            now_utc=now_utc.timestamp(),
        )
    except StaleInspectionToken as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"egress inspection failed: {exc}"})

    chain_ok, _ = AUDIT_LOG.verify()
    return {
        "status": "inspected",
        "policy_reason": policy_reason,
        "fencing_token": lease.fencing_token,
        "audit_chain_valid": chain_ok,
        "inspection": {
            "route_key": res.route_key,
            "source_cidr": res.source_cidr,
            "destination_port": res.destination_port,
            "protocol": res.protocol,
            "ngfw_profile": res.ngfw_profile,
            "action": res.action,
            "s3_bucket": res.s3_bucket,
            "s3_key": res.s3_key,
            "audit_hash": res.audit_hash,
        },
    }

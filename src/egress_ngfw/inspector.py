from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import logging
import threading
import time
from typing import Any

from storage.audit_log import HashChainedAuditLog

logger = logging.getLogger("egress_ngfw.inspector")


class EgressLeaseConflict(Exception):
    pass


class StaleInspectionToken(Exception):
    pass


@dataclass
class InspectionLease:
    route_key: str
    holder_id: str
    fencing_token: int
    expires_at_utc: float


@dataclass
class InspectionResult:
    route_key: str
    source_cidr: str
    destination_port: int
    protocol: str
    ngfw_profile: str
    action: str
    fencing_token: int
    s3_bucket: str
    s3_key: str
    audit_hash: str


def sign_egress_request(secret: str, ts_unix: int, body: bytes) -> str:
    msg = f"{ts_unix}.".encode("utf-8") + body
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify_egress_request(
    secret: str,
    signature: str | None,
    timestamp: str | None,
    body: bytes,
    max_skew_sec: int = 300,
    now_unix: int | None = None,
) -> tuple[bool, str]:
    if not signature or not timestamp:
        return False, "missing X-Signature-256 or X-Timestamp header"
    try:
        ts = int(timestamp.strip())
    except ValueError:
        return False, "invalid X-Timestamp header"

    # Evaluate in UTC epoch seconds so Daylight Saving Time transitions never shift replay windows.
    now = int(time.time()) if now_unix is None else now_unix
    if abs(now - ts) > max_skew_sec:
        return False, "timestamp outside replay window"

    expected = sign_egress_request(secret, ts, body)
    if not hmac.compare_digest(expected, signature.strip()):
        return False, "hmac signature mismatch"
    return True, "ok"


def _retryable_aws_error(exc: Any) -> bool:
    resp = getattr(exc, "response", {}) or {}
    code = resp.get("Error", {}).get("Code", "")
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    return code in {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
    } or status in {429, 502, 503, 504}


def _call_aws_retry(op: str, fn: Any, exc_cls: Any, attempts: int = 4) -> Any:
    backoff = 0.1
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except exc_cls as exc:
            if not _retryable_aws_error(exc) or attempt == attempts:
                raise
            # Cap per-retry delay at 2.0s so NGFW inspection requests do not exceed caller timeouts.
            pause = min(backoff, 2.0)
            logger.warning("retrying aws op=%s attempt=%d pause_s=%.2f err=%s", op, attempt, pause, exc)
            time.sleep(pause)
            backoff *= 2.0


class EgressLeaseManager:
    # Monotonic fencing tokens prevent a stalled worker from applying stale NGFW route state after takeover.
    def __init__(self, audit_log: HashChainedAuditLog | None = None, ttl_sec: float = 25.0) -> None:
        self._lock = threading.Lock()
        self._leases: dict[str, InspectionLease] = {}
        self._token_seq: int = 0
        self._audit = audit_log or HashChainedAuditLog()
        self._ttl_sec = ttl_sec

    def acquire(
        self,
        route_key: str,
        holder_id: str,
        now_utc: float | None = None,
        grace_extension_sec: float = 0.0,
    ) -> InspectionLease:
        now = time.time() if now_utc is None else now_utc
        clamped_grace = min(max(grace_extension_sec, 0.0), 900.0)
        with self._lock:
            existing = self._leases.get(route_key)
            if existing is not None and existing.expires_at_utc > now and existing.holder_id != holder_id:
                raise EgressLeaseConflict(f"route {route_key} actively leased by {existing.holder_id}")

            self._token_seq += 1
            lease = InspectionLease(
                route_key=route_key,
                holder_id=holder_id,
                fencing_token=self._token_seq,
                expires_at_utc=now + self._ttl_sec + clamped_grace,
            )
            self._leases[route_key] = lease
            self._audit.append(
                event_type="egress_lease_acquired",
                fencing_token=lease.fencing_token,
                payload={
                    "route_key": route_key,
                    "holder_id": holder_id,
                    "expires_at_utc": lease.expires_at_utc,
                    "grace_sec": clamped_grace,
                    "recorded_at_utc": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                },
            )
            return lease

    def check_token(self, route_key: str, fencing_token: int, now_utc: float | None = None) -> bool:
        now = time.time() if now_utc is None else now_utc
        with self._lock:
            lease = self._leases.get(route_key)
            if lease is None:
                return False
            if lease.expires_at_utc <= now:
                return False
            return fencing_token == lease.fencing_token

    def audit_log(self) -> HashChainedAuditLog:
        return self._audit

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "leases": {
                    k: {
                        "holder_id": v.holder_id,
                        "fencing_token": v.fencing_token,
                        "expires_at_utc": v.expires_at_utc,
                    }
                    for k, v in self._leases.items()
                },
                "audit_events": len(self._audit.events()),
            }


class CentralizedEgressInspector:
    def __init__(
        self,
        lease_manager: EgressLeaseManager,
        region: str = "us-east-1",
        endpoint_url: str | None = "http://localhost:4566",
        bucket: str = "centralized-egress-ngfw-audit",
        ec2_client: Any | None = None,
        s3_client: Any | None = None,
        client_error_cls: Any | None = None,
    ) -> None:
        self.leases = lease_manager
        self.region = region
        self.bucket = bucket

        if client_error_cls is not None:
            self._client_error = client_error_cls
            boto3_mod = None
        else:
            try:
                import boto3
                from botocore.exceptions import ClientError

                boto3_mod = boto3
                self._client_error = ClientError
            except ImportError:
                boto3_mod = None

                class _FallbackError(Exception):
                    response: dict[str, Any] = {}

                self._client_error = _FallbackError

        client_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
            client_kwargs["aws_access_key_id"] = "test"
            client_kwargs["aws_secret_access_key"] = "test"

        if ec2_client is not None:
            self.ec2 = ec2_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when ec2_client is not supplied")
            self.ec2 = boto3_mod.client("ec2", **client_kwargs)

        if s3_client is not None:
            self.s3 = s3_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when s3_client is not supplied")
            self.s3 = boto3_mod.client("s3", **client_kwargs)

    def _ensure_bucket(self) -> None:
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except self._client_error:
            try:
                self.s3.create_bucket(Bucket=self.bucket)
            except self._client_error as exc:
                code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
                if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    raise

    def inspect_and_route(
        self,
        source_cidr: str,
        destination_port: int,
        protocol: str,
        ngfw_profile: str,
        fencing_token: int,
        now_utc: float | None = None,
    ) -> InspectionResult:
        net = ipaddress.ip_network(source_cidr, strict=False)
        route_key = f"{net}/{protocol}/{destination_port}"

        if not self.leases.check_token(route_key=route_key, fencing_token=fencing_token, now_utc=now_utc):
            raise StaleInspectionToken(f"fencing token {fencing_token} rejected for {route_key}")

        _call_aws_retry(
            "ec2:describe_transit_gateway_attachments",
            lambda: self.ec2.describe_transit_gateway_attachments(),
            self._client_error,
        )
        self._ensure_bucket()

        action = "allow_inspect" if ngfw_profile in {"tls-inspect-strict", "dns-l7-guard", "egress-default-inspect"} else "block"
        ts = time.time() if now_utc is None else now_utc
        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        ev = self.leases.audit_log().append(
            event_type="egress_ngfw_routed",
            fencing_token=fencing_token,
            payload={
                "route_key": route_key,
                "source_cidr": str(net),
                "destination_port": destination_port,
                "protocol": protocol,
                "ngfw_profile": ngfw_profile,
                "action": action,
                "inspected_at_utc": dt_utc.isoformat(),
            },
        )
        safe_key = route_key.replace("/", "_")
        s3_key = f"ngfw-logs/{dt_utc.strftime('%Y-%m-%d')}/{safe_key}-tok{fencing_token}.json"
        doc = {
            "route_key": route_key,
            "source_cidr": str(net),
            "destination_port": destination_port,
            "protocol": protocol,
            "ngfw_profile": ngfw_profile,
            "action": action,
            "fencing_token": fencing_token,
            "audit_hash": ev.entry_hash,
        }
        _call_aws_retry(
            "s3:put_object",
            lambda: self.s3.put_object(
                Bucket=self.bucket,
                Key=s3_key,
                Body=json.dumps(doc, indent=2).encode("utf-8"),
                ContentType="application/json",
            ),
            self._client_error,
        )
        return InspectionResult(
            route_key=route_key,
            source_cidr=str(net),
            destination_port=destination_port,
            protocol=protocol,
            ngfw_profile=ngfw_profile,
            action=action,
            fencing_token=fencing_token,
            s3_bucket=self.bucket,
            s3_key=s3_key,
            audit_hash=ev.entry_hash,
        )

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.egress_ngfw.inspector import CentralizedEgressInspector, EgressLeaseManager
from storage.audit_log import HashChainedAuditLog

SEED_FLOWS = [
    ("10.50.1.0/24", 443, "tcp", "tls-inspect-strict", "seed-worker-1"),
    ("10.50.2.0/24", 53, "udp", "dns-l7-guard", "seed-worker-1"),
    ("10.50.3.0/24", 8443, "tcp", "egress-default-inspect", "seed-worker-1"),
]


def seed_flows(inspector: CentralizedEgressInspector, leases: EgressLeaseManager, now_utc: float = 1764267000.0) -> list[dict]:
    results = []
    for idx, (cidr, port, proto, profile, holder) in enumerate(SEED_FLOWS, start=1):
        route_key = f"{cidr}/{proto}/{port}"
        lease = leases.acquire(route_key=route_key, holder_id=holder, now_utc=now_utc + idx)
        res = inspector.inspect_and_route(
            source_cidr=cidr,
            destination_port=port,
            protocol=proto,
            ngfw_profile=profile,
            fencing_token=lease.fencing_token,
            now_utc=now_utc + idx,
        )
        results.append({
            "route_key": res.route_key,
            "ngfw_profile": res.ngfw_profile,
            "s3_key": res.s3_key,
            "audit_hash": res.audit_hash,
        })
    return results


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env_file = root / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    log = HashChainedAuditLog()
    leases = EgressLeaseManager(audit_log=log, ttl_sec=60.0)
    inspector = CentralizedEgressInspector(
        lease_manager=leases,
        region=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566"),
        bucket=os.getenv("EGRESS_AUDIT_BUCKET", "centralized-egress-ngfw-audit"),
    )
    seeded = seed_flows(inspector, leases)
    print(json.dumps({"seeded_count": len(seeded), "chain_valid": log.verify()[0], "flows": seeded}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

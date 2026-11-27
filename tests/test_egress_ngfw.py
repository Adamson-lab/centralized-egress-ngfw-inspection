import os
import sys
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.check_env import run_preflight
from scripts.seed_egress_baseline import seed_flows
from src.egress_ngfw.inspector import (
    CentralizedEgressInspector,
    EgressLeaseConflict,
    EgressLeaseManager,
    StaleInspectionToken,
    sign_egress_request,
    verify_egress_request,
)
from storage.audit_log import HashChainedAuditLog


class TestCentralizedEgressNgfw(unittest.TestCase):
    def setUp(self) -> None:
        self.log = HashChainedAuditLog()
        self.leases = EgressLeaseManager(audit_log=self.log, ttl_sec=25.0)
        self.fake_ec2 = MagicMock()
        self.fake_ec2.describe_transit_gateway_attachments.return_value = {"TransitGatewayAttachments": []}
        self.fake_s3 = MagicMock()
        self.inspector = CentralizedEgressInspector(
            lease_manager=self.leases,
            region="us-east-1",
            endpoint_url=None,
            bucket="test-egress-ngfw-bucket",
            ec2_client=self.fake_ec2,
            s3_client=self.fake_s3,
        )

    def test_inspect_flow_and_verify_chain(self) -> None:
        t0 = 1764267000.0
        lease = self.leases.acquire("10.50.1.0/24/tcp/443", "ngfw-worker-1", now_utc=t0, grace_extension_sec=600.0)
        res = self.inspector.inspect_and_route(
            source_cidr="10.50.1.0/24",
            destination_port=443,
            protocol="tcp",
            ngfw_profile="tls-inspect-strict",
            fencing_token=lease.fencing_token,
            now_utc=t0 + 1,
        )
        self.assertEqual(res.action, "allow_inspect")
        ok, msg = self.log.verify()
        self.assertTrue(ok, msg)
        self.fake_s3.put_object.assert_called_once()

    def test_seed_flows_and_lease_conflict(self) -> None:
        seeded = seed_flows(self.inspector, self.leases, now_utc=1764267000.0)
        self.assertEqual(len(seeded), 3)
        ok, _ = self.log.verify()
        self.assertTrue(ok)

        with self.assertRaises(EgressLeaseConflict):
            self.leases.acquire("10.50.1.0/24/tcp/443", "ngfw-worker-2", now_utc=1764267002.0)

    def test_chaos_stale_token_rejected_after_takeover(self) -> None:
        t0 = 1764267000.0
        stale = self.leases.acquire("10.50.9.0/24/tcp/443", "ngfw-worker-1", now_utc=t0)
        # Worker-1 stalls past TTL and worker-2 takes ownership with a higher fencing token.
        fresh = self.leases.acquire("10.50.9.0/24/tcp/443", "ngfw-worker-2", now_utc=t0 + 30)
        self.assertGreater(fresh.fencing_token, stale.fencing_token)

        with self.assertRaises(StaleInspectionToken):
            self.inspector.inspect_and_route(
                source_cidr="10.50.9.0/24",
                destination_port=443,
                protocol="tcp",
                ngfw_profile="tls-inspect-strict",
                fencing_token=stale.fencing_token,
                now_utc=t0 + 31,
            )

    def test_hmac_and_preflight_no_live(self) -> None:
        secret = "egress-secret"
        body = b'{"source_cidr":"10.50.1.0/24","destination_port":443}'
        now = 1764267000
        sig = sign_egress_request(secret, now, body)
        ok, _ = verify_egress_request(secret, sig, str(now), body, now_unix=now)
        self.assertTrue(ok)
        self.assertEqual(run_preflight(check_live=False), 0)

    def test_bench_lease_and_audit(self) -> None:
        log = HashChainedAuditLog()
        mgr = EgressLeaseManager(audit_log=log, ttl_sec=30.0)
        base = 1764267000.0
        iters = 2000
        t0 = time.perf_counter()
        for i in range(iters):
            rk = f"10.60.{i % 8}.0/24/tcp/443"
            lease = mgr.acquire(rk, f"w-{i % 3}", now_utc=base + (i * 35.0))
            self.assertTrue(mgr.check_token(rk, lease.fencing_token, now_utc=base + (i * 35.0)))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ok, _ = log.verify()
        self.assertTrue(ok)
        print(f"BENCH lease+check+audit ({iters} ops): {elapsed_ms:.2f} ms ({(elapsed_ms / iters) * 1000:.2f} us/op)")


if __name__ == "__main__":
    unittest.main()

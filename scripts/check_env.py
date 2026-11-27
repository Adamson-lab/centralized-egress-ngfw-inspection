import os
from pathlib import Path
import sys
import urllib.request


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def run_preflight(check_live: bool = True) -> int:
    root = Path(__file__).resolve().parents[1]
    _load_dotenv(root / ".env.local")
    _load_dotenv(root / ".env")

    failures: list[str] = []
    region = os.getenv("AWS_REGION", "us-east-1").strip()
    bucket = os.getenv("EGRESS_AUDIT_BUCKET", "centralized-egress-ngfw-audit").strip()
    opa_url = os.getenv("OPA_URL", "http://localhost:8181").strip().rstrip("/")
    endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566").strip()

    if not region:
        failures.append("x AWS_REGION is empty")
    if len(bucket) < 3:
        failures.append("x EGRESS_AUDIT_BUCKET must be at least 3 characters")

    if not check_live:
        if failures:
            for f in failures:
                print(f)
            return 1
        print(f"ok config validated for region={region} bucket={bucket}")
        return 0

    try:
        import boto3
    except ImportError:
        print("x boto3 is not installed in the active Python environment")
        return 1

    kwargs: dict[str, str] = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
        kwargs["aws_access_key_id"] = os.getenv("AWS_ACCESS_KEY_ID", "test")
        kwargs["aws_secret_access_key"] = os.getenv("AWS_SECRET_ACCESS_KEY", "test")

    try:
        sts = boto3.client("sts", **kwargs)
        ident = sts.get_caller_identity()
        print(f"ok sts caller identity verified (account={ident.get('Account', 'unknown')})")
    except Exception as exc:
        failures.append(f"x sts caller identity check failed: {exc}")

    try:
        s3 = boto3.client("s3", **kwargs)
        probe_key = "_preflight/probe-check.txt"
        s3.put_object(Bucket=bucket, Key=probe_key, Body=b"ok")
        s3.delete_object(Bucket=bucket, Key=probe_key)
        print(f"ok s3 write/delete probe succeeded on bucket={bucket}")
    except Exception as exc:
        failures.append(f"x s3 write/delete probe failed on bucket={bucket}: {exc}")

    try:
        with urllib.request.urlopen(f"{opa_url}/health", timeout=2.5) as resp:
            if resp.status != 200:
                failures.append(f"x opa health check returned status {resp.status}")
            else:
                print(f"ok opa reachable at {opa_url}")
    except Exception as exc:
        failures.append(f"x opa health probe failed at {opa_url}: {exc}")

    if failures:
        for f in failures:
            print(f)
        return 1
    return 0


if __name__ == "__main__":
    live = "--no-live" not in sys.argv
    sys.exit(run_preflight(check_live=live))

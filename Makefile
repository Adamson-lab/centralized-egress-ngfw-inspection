SHELL := /bin/bash
COMPOSE_FILE := deploy/docker-compose.yml

.PHONY: up down doctor seed run test chaos bench lint

up:
	docker compose -f $(COMPOSE_FILE) up -d --wait

down:
	docker compose -f $(COMPOSE_FILE) down -v

doctor:
	python3 scripts/check_env.py

seed:
	python3 scripts/seed_egress_baseline.py

lint:
	python3 -m py_compile src/egress_ngfw/inspector.py src/egress_ngfw/server.py scripts/check_env.py scripts/seed_egress_baseline.py storage/audit_log.py tests/test_egress_ngfw.py

run:
	AWS_ENDPOINT_URL=http://localhost:4566 \
	OPA_URL=http://localhost:8181 \
	EGRESS_AUDIT_BUCKET=centralized-egress-ngfw-audit \
	WEBHOOK_HMAC_SECRET=local-dev-egress-ngfw-secret \
	uvicorn src.egress_ngfw.server:app --host 0.0.0.0 --port 8080

test:
	python3 -m unittest discover -s tests -p "test_*.py" -v

chaos:
	python3 -m unittest tests/test_egress_ngfw.py -k test_chaos_stale_token_rejected_after_takeover -v

bench:
	python3 -m unittest tests/test_egress_ngfw.py -k test_bench_lease_and_audit -v

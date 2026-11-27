# Design Notes: Centralized Egress Inspection with Next-Gen Firewalls

This service separates lease and hash-chained audit logging (`src/egress_ngfw/inspector.py`, `src/egress_ngfw/server.py`, `storage/audit_log.py`) from centralized egress routing and AWS EC2/S3 recording (`CentralizedEgressInspector`) with Open Policy Agent (OPA) policy evaluation.

## Trust-Boundary and Network Enclave Topology

```mermaid
flowchart TB
    subgraph CallerZone["Caller Zone"]
        Caller["Caller"]
    end

    subgraph ControlZone["Control Plane"]
        API["FastAPI Server :8080"]
        LeaseMgr["EgressLeaseManager"]
        AuditLog["HashChainedAuditLog"]
        API --> LeaseMgr
        LeaseMgr --> AuditLog
    end

    subgraph PolicyCloud["Policy and Cloud Services"]
        OPA["OPA :8181"]
        AWS["LocalStack EC2, S3 & STS :4566"]
    end

    subgraph InspectionZone["Inspection Execution"]
        Inspector["CentralizedEgressInspector"]
    end

    Caller -->|"HTTP + HMAC-SHA256 :8080"| API
    API -->|"HTTP REST Rego Eval :8181"| OPA
    API --> Inspector
    Inspector -->|"check_token"| LeaseMgr
    Inspector -->|"boto3 EC2 & S3 :4566"| AWS
```

## Inspection and Failure Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant S as FastAPI Server :8080
    participant O as OPA :8181
    participant L as EgressLeaseManager
    participant I as CentralizedEgressInspector

    C->>S: POST /v1/egress/inspect
    S->>S: verify_egress_request
    alt Invalid signature or stale timestamp
        S-->>C: 401 Unauthorized
    else Signature valid
        par Policy checks
            S->>O: POST /v1/data/egress/ngfw
            S->>O: POST /v1/data/egress/window
        end
        alt Policy denied
            S-->>C: 403 Forbidden
        else Policy allowed
            critical Lease acquisition
                S->>L: acquire(route_key, holder_id)
            option Active lease conflict
                S-->>C: 409 Conflict
            end
            S->>I: inspect_and_route(fencing_token)
            alt Stale or expired token
                I-->>S: StaleInspectionToken
                S-->>C: 409 Conflict
            else Valid token
                I-->>S: InspectionResult
                S-->>C: 200 OK
            end
        end
    end
```

## Route Lease Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Active: acquire() issues next fencing_token
    note right of Active: Token checked before EC2 attachment query and S3 write
    Active --> Active: same holder re-acquires or extends grace
    Active --> Expired: expires_at_utc reached
    Expired --> Active: new holder acquires higher fencing_token
    Active --> [*]
```

## Trade-Offs and Limitations

Timestamps and UTC change windows use UTC so Daylight Saving Time transitions do not shift allowed hours. Off-window changes permit up to a 15-minute grace extension when an active incident ID is supplied. AWS calls retry transient errors up to 4 times with per-retry delay capped at `2.0s`.

Limitations: `EgressLeaseManager` and `HashChainedAuditLog` are in-memory per process, and `describe_transit_gateway_attachments` reads the initial page without `NextToken` pagination.

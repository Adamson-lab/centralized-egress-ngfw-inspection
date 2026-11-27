package egress.window

import rego.v1

default allow := false
default reason := "denied: egress rule mutation outside UTC change window without active incident grace lock"

# Allow off-window NGFW rule updates up to 15 minutes when an active incident grace lock is present.
grace_active if {
	input.grace_lock.active == true
	count(input.grace_lock.incident_id) >= 4
	input.grace_lock.extra_minutes <= 15
	input.operator_role in {"sec-ngfw", "incident-lead"}
}

allow if {
	grace_active
}

allow if {
	not grace_active
	input.operator_role in {"sec-ngfw", "incident-lead", "egress-bot"}
	input.utc_hour >= 1
	input.utc_hour <= 23
}

reason := "allowed via active 15m incident grace lock" if {
	allow
	grace_active
}

reason := "allowed within UTC egress change window" if {
	allow
	not grace_active
}

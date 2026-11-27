package egress.ngfw

import rego.v1

default allow := false
default reason := "denied: destination port, protocol, or NGFW inspection profile rejected"

allow if {
	input.ngfw_profile in {"tls-inspect-strict", "dns-l7-guard", "egress-default-inspect"}
	input.destination_port in {443, 8443, 53}
	input.protocol in {"tcp", "udp"}
	input.source_cidr != ""
}

reason := "allowed: egress flow routed through NGFW inspection profile" if {
	allow
}

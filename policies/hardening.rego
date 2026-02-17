# ============================================================================
# OPA Performance & Hardening Policies for dnsdist Configuration
# ============================================================================
# Validates production-readiness: performance tuning, resource limits,
# redundancy, and defense-in-depth hardening.
# ============================================================================

package dnsdist.hardening

import future.keywords.in
import future.keywords.contains
import future.keywords.if
import future.keywords.every

# --------------------------------------------------------------------------
# HARDENING CHECKS
# --------------------------------------------------------------------------

# ===========================
# REDUNDANCY
# ===========================

finding contains msg if {
	input.backends
	count(input.backends) < 2
	msg := "HARDENING [HA-01]: Fewer than 2 backends configured. No failover is possible if the single backend fails."
}

finding contains msg if {
	input.binds
	_all_binds_single_address_family
	msg := "HARDENING [HA-02]: All bind addresses use the same address family. Consider dual-stack (IPv4 + IPv6) listeners."
}

finding contains msg if {
	input.backends
	_all_backends_same_subnet
	msg := "HARDENING [HA-03]: All backends appear to be in the same /24 subnet. Consider geographic or network diversity."
}

# ===========================
# PERFORMANCE TUNING
# ===========================

finding contains msg if {
	input.general
	input.general.threads
	input.general.threads < 2
	msg := sprintf("HARDENING [PERF-01]: Only %d thread(s) configured. Production systems should use multiple threads (typically 2-16).", [input.general.threads])
}

finding contains msg if {
	input.binds
	some i, bind in input.binds
	bind.reuseport == false
	msg := sprintf("HARDENING [PERF-02]: Bind #%d (%s) has reuseport disabled. SO_REUSEPORT distributes load across threads.", [i, bind.listen_address])
}

finding contains msg if {
	input.backends
	some i, backend in input.backends
	backend.sockets
	backend.sockets < 2
	msg := sprintf("HARDENING [PERF-03]: Backend #%d (%s) uses only %d socket(s). Multiple sockets improve throughput to multi-threaded backends.", [i, backend.address, backend.sockets])
}

finding contains msg if {
	not input.cache_settings
	not _any_pool_has_cache
	msg := "HARDENING [PERF-04]: No caching is configured anywhere. Response caching significantly reduces backend load and latency."
}

finding contains msg if {
	input.cache_settings
	input.cache_settings.max_entries
	input.cache_settings.max_entries < 10000
	msg := sprintf("HARDENING [PERF-05]: Global cache has only %d max entries. Production caches typically need 100k+ entries.", [input.cache_settings.max_entries])
}

finding contains msg if {
	input.tuning
	input.tuning.tcp
	input.tuning.tcp.max_idle_time
	input.tuning.tcp.max_idle_time > 300
	msg := sprintf("HARDENING [PERF-06]: TCP max idle time is %d seconds. High values can exhaust file descriptors under attack.", [input.tuning.tcp.max_idle_time])
}

finding contains msg if {
	input.tuning
	input.tuning.tcp
	input.tuning.tcp.max_concurrent_connections
	input.tuning.tcp.max_concurrent_connections > 100000
	msg := sprintf("HARDENING [PERF-07]: TCP max concurrent connections is %d. Extremely high limits may cause OOM under SYN floods.", [input.tuning.tcp.max_concurrent_connections])
}

# ===========================
# DEFENSE-IN-DEPTH
# ===========================

finding contains msg if {
	not input.dynamic_rules
	msg := "HARDENING [DID-01]: No dynamic rules configured. Dynamic rules provide adaptive rate limiting against DDoS and abuse."
}

finding contains msg if {
	input.query_rules
	not _has_drop_action
	msg := "HARDENING [DID-02]: No Drop actions in query rules. Consider blocking known-bad traffic patterns (e.g., ANY queries over UDP)."
}

finding contains msg if {
	input.query_rules
	not _has_tc_action
	msg := "HARDENING [DID-03]: No TC (Truncate) actions in query rules. TC is useful for forcing UDP reflection attack traffic to TCP."
}

finding contains msg if {
	input.binds
	some bind in input.binds
	bind.protocol in ["DoH", "DoH3"]
	not bind.doh
	msg := "HARDENING [DID-04]: DoH bind has no DoH-specific configuration. Consider setting custom URL paths and response maps."
}

finding contains msg if {
	not _has_edns_client_subnet_config
	msg := "HARDENING [DID-05]: No EDNS Client Subnet (ECS) configuration found. Consider configuring ECS for CDN-aware DNS if applicable."
}

finding contains msg if {
	input.general
	input.general.keep_capabilities
	some cap in input.general.keep_capabilities
	cap == "CAP_SYS_ADMIN"
	msg := "HARDENING [DID-06]: CAP_SYS_ADMIN is retained after privilege drop. This is a broad capability — only retain if needed for eBPF."
}

# ===========================
# MONITORING READINESS
# ===========================

finding contains msg if {
	not input.webserver
	msg := "HARDENING [MON-01]: No webserver configured. The built-in webserver exposes Prometheus metrics and health-check endpoints."
}

finding contains msg if {
	input.webserver
	input.webserver.api_enabled == false
	msg := "HARDENING [MON-02]: Webserver API is disabled. The API provides runtime statistics and configuration inspection."
}

finding contains msg if {
	not input.carbon
	msg := "HARDENING [MON-03]: No Carbon/Graphite export configured. Consider enabling for time-series metrics collection."
}

# ===========================
# LOAD BALANCING
# ===========================

finding contains msg if {
	input.load_balancing_policies
	input.load_balancing_policies.default_policy == "roundrobin"
	msg := "HARDENING [LB-01]: Round-robin does not account for backend health or load. Consider 'leastOutstanding' for adaptive balancing."
}

finding contains msg if {
	input.load_balancing_policies
	input.load_balancing_policies.default_policy == "random"
	msg := "HARDENING [LB-02]: Random server selection does not account for backend health or load. Consider 'leastOutstanding'."
}

finding contains msg if {
	input.backends
	some i, backend in input.backends
	backend.health_check
	backend.health_check.check_interval
	backend.health_check.check_interval > 30
	msg := sprintf("HARDENING [LB-03]: Backend #%d (%s) health check interval is %d seconds. Slow checks delay failover.", [i, backend.address, backend.health_check.check_interval])
}

# --------------------------------------------------------------------------
# HELPER RULES
# --------------------------------------------------------------------------

_all_binds_single_address_family if {
	every bind in input.binds {
		_is_ipv4(bind.listen_address)
	}
}

_all_binds_single_address_family if {
	every bind in input.binds {
		_is_ipv6(bind.listen_address)
	}
}

_is_ipv4(addr) if {
	not contains(addr, "[")
	not contains(addr, "::")
}

_is_ipv6(addr) if {
	contains(addr, "[")
}

_is_ipv6(addr) if {
	contains(addr, "::")
}

_all_backends_same_subnet if {
	count(input.backends) > 1
	subnets := {s |
		some backend in input.backends
		s := _extract_subnet(backend.address)
	}
	count(subnets) == 1
}

# Rough extraction: take first 3 octets of an IPv4 address
_extract_subnet(addr) := subnet if {
	clean := trim_left(addr, "[")
	parts := split(clean, ".")
	count(parts) >= 3
	subnet := concat(".", [parts[0], parts[1], parts[2]])
}

_any_pool_has_cache if {
	input.pools
	some _, pool in input.pools
	pool.cache
}

_has_drop_action if {
	some rule in input.query_rules
	rule.action.type == "Drop"
}

_has_tc_action if {
	some rule in input.query_rules
	rule.action.type in ["TC", "Truncate"]
}

_has_edns_client_subnet_config if {
	input.edns_client_subnet
}

_has_edns_client_subnet_config if {
	some backend in input.backends
	backend.edns_client_subnet
}

# --------------------------------------------------------------------------
# SUMMARY
# --------------------------------------------------------------------------

total_findings := count(finding)

hardening_score := score if {
	max_checks := 16
	passed := max_checks - count(finding)
	score := sprintf("%d/%d checks passed", [passed, max_checks])
}

report := {
	"total_findings": total_findings,
	"findings": finding,
	"score": hardening_score,
}

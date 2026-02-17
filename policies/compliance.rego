# ============================================================================
# OPA Compliance Policies for dnsdist Configuration
# ============================================================================
# Enforces organizational and regulatory compliance requirements.
# Covers: encryption mandates, audit logging, access control, data residency.
#
# Usage:
#   conftest test dnsdist.yml -p policy/
#   opa eval -i dnsdist.json -d policy/ "data.dnsdist.compliance"
# ============================================================================

package dnsdist.compliance

import future.keywords.in
import future.keywords.contains
import future.keywords.if
import future.keywords.every

# --------------------------------------------------------------------------
# COMPLIANCE VIOLATIONS — strict enforcement
# --------------------------------------------------------------------------

# ===========================
# ENCRYPTION IN TRANSIT
# ===========================

violation contains msg if {
	input.binds
	not _has_encrypted_bind
	msg := "COMPLIANCE [ENCRYPT-01]: No encrypted listener (DoT/DoH/DoH3/DoQ) is configured. Encryption-in-transit is required."
}

violation contains msg if {
	input.backends
	not _has_encrypted_backend
	msg := "COMPLIANCE [ENCRYPT-02]: No encrypted backend connection (DoT/DoH) is configured. Backend traffic must be encrypted if traversing untrusted networks."
}

violation contains msg if {
	some i, bind in input.binds
	bind.tls
	not bind.tls.ocsp_stapling
	bind.protocol in ["DoT", "DoH", "DoH3"]
	msg := sprintf("COMPLIANCE [ENCRYPT-03]: Bind #%d (%s) does not have OCSP stapling configured for '%s'. OCSP stapling improves TLS verification.", [i, bind.listen_address, bind.protocol])
}

# ===========================
# ACCESS CONTROL
# ===========================

violation contains msg if {
	not input.acl
	msg := "COMPLIANCE [ACL-01]: No ACL is defined. Explicit access control lists are required."
}

violation contains msg if {
	input.acl
	_acl_has_public_range
	msg := "COMPLIANCE [ACL-02]: ACL includes a public/unrestricted range (0.0.0.0/0 or ::/0). ACLs must be scoped to specific networks."
}

violation contains msg if {
	input.console
	not input.console.acl
	msg := "COMPLIANCE [ACL-03]: Console does not have a dedicated ACL. Management interfaces require explicit access control."
}

violation contains msg if {
	input.webserver
	not input.webserver.acl
	msg := "COMPLIANCE [ACL-04]: Webserver does not have a dedicated ACL. Management interfaces require explicit access control."
}

# ===========================
# AUTHENTICATION
# ===========================

violation contains msg if {
	input.console
	not input.console.key
	msg := "COMPLIANCE [AUTH-01]: Console encryption key is not set. Console sessions must be encrypted."
}

violation contains msg if {
	input.webserver
	input.webserver.api_enabled == true
	not input.webserver.api_key
	msg := "COMPLIANCE [AUTH-02]: API is enabled without an API key. API endpoints must be authenticated."
}

violation contains msg if {
	input.webserver
	not input.webserver.password
	msg := "COMPLIANCE [AUTH-03]: Webserver password is not set. Web management interface must be authenticated."
}

# ===========================
# AUDIT LOGGING
# ===========================

violation contains msg if {
	not input.dnstap_loggers
	not input.carbon
	not _has_logging_action
	msg := "COMPLIANCE [LOG-01]: No audit logging is configured (no dnstap, carbon, or logging actions). Query/response logging is required for audit compliance."
}

violation contains msg if {
	input.console
	input.console.log_connections
	input.console.log_connections == false
	msg := "COMPLIANCE [LOG-02]: Console connection logging is disabled. Management access must be logged."
}

# ===========================
# PRIVILEGE MANAGEMENT
# ===========================

violation contains msg if {
	not input.general
	msg := "COMPLIANCE [PRIV-01]: No 'general' section — cannot verify privilege dropping (setuid/setgid). dnsdist should not run as root."
}

violation contains msg if {
	input.general
	not input.general.setuid
	msg := "COMPLIANCE [PRIV-02]: No setuid configured. dnsdist should drop privileges to a non-root user after startup."
}

violation contains msg if {
	input.general
	not input.general.setgid
	msg := "COMPLIANCE [PRIV-03]: No setgid configured. dnsdist should drop privileges to a non-root group after startup."
}

# ===========================
# NAMING & IDENTIFICATION
# ===========================

violation contains msg if {
	not input.general
	msg := "COMPLIANCE [ID-01]: No general configuration. server_id must be set for asset identification."
}

violation contains msg if {
	input.general
	not input.general.server_id
	msg := "COMPLIANCE [ID-02]: server_id is not set. Each dnsdist instance must have a unique identifier for inventory and audit trails."
}

# ===========================
# DNSSEC
# ===========================

violation contains msg if {
	input.backends
	some i, backend in input.backends
	backend.skip_validation == true
	msg := sprintf("COMPLIANCE [DNSSEC-01]: Backend #%d (%s) has DNSSEC validation explicitly skipped. DNSSEC validation should not be disabled in compliant environments.", [i, backend.address])
}

# ===========================
# RATE LIMITING / DDoS PROTECTION
# ===========================

violation contains msg if {
	not input.dynamic_rules
	not _has_rate_limit_rule
	msg := "COMPLIANCE [RATE-01]: No rate limiting is configured (neither dynamic rules nor QPS-based query rules). Rate limiting is required to mitigate abuse."
}

# --------------------------------------------------------------------------
# HELPER RULES
# --------------------------------------------------------------------------

_has_encrypted_bind if {
	some bind in input.binds
	bind.protocol in ["DoT", "DoH", "DoH3", "DoQ", "DNSCrypt"]
}

_has_encrypted_backend if {
	some backend in input.backends
	backend.protocol in ["DoT", "DoH"]
}

_acl_has_public_range if {
	some entry in input.acl
	entry in ["0.0.0.0/0", "::/0"]
}

_has_logging_action if {
	input.query_rules
	some rule in input.query_rules
	rule.action
	rule.action.type in ["Log", "RemoteLog", "DnstapLog"]
}

_has_rate_limit_rule if {
	input.query_rules
	some rule in input.query_rules
	rule.selector
	rule.selector.type in ["MaxQPSIP", "MaxQPS", "QPS", "QPSAction"]
}

# --------------------------------------------------------------------------
# COMPLIANCE SUMMARY
# --------------------------------------------------------------------------

compliance_status := "PASS" if {
	count(violation) == 0
}

compliance_status := "FAIL" if {
	count(violation) > 0
}

compliance_report := {
	"status": compliance_status,
	"total_violations": count(violation),
	"violations": violation,
}

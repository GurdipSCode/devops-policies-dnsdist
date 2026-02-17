# devops-policies-dnsdist

Comprehensive Open Policy Agent (OPA) Rego policies for validating **dnsdist 2.x YAML configuration files** against security best practices, compliance requirements, and production-readiness standards.

## Policy Modules

| File | Package | Purpose |
|------|---------|---------|
| `dnsdist.rego` | `dnsdist` | Core validation: backends, binds, ACLs, TLS, console, webserver, cache, query rules, proxy protocol, DoH, DNSCrypt, logging |
| `compliance.rego` | `dnsdist.compliance` | Regulatory/org compliance: encryption-in-transit, access control, authentication, audit logging, privilege management, DNSSEC, rate limiting |
| `hardening.rego` | `dnsdist.hardening` | Production hardening: redundancy, performance tuning, defense-in-depth, monitoring readiness, load balancing |

## Quick Start

### Using Conftest

```bash
# Install conftest
brew install conftest  # or download from https://www.conftest.dev

# Test your dnsdist config
conftest test /etc/dnsdist/dnsdist.yml -p policy/

# Test with specific namespace
conftest test dnsdist.yml -p policy/ --namespace dnsdist.compliance

# Output as JSON
conftest test dnsdist.yml -p policy/ -o json
```

### Using OPA CLI

```bash
# Convert YAML to JSON first
yq eval -o json dnsdist.yml > dnsdist.json

# Evaluate deny rules
opa eval -i dnsdist.json -d policy/ "data.dnsdist.deny"

# Evaluate compliance violations
opa eval -i dnsdist.json -d policy/ "data.dnsdist.compliance.compliance_report"

# Evaluate hardening findings
opa eval -i dnsdist.json -d policy/ "data.dnsdist.hardening.report"
```

### In CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Validate dnsdist config
  run: |
    conftest test config/dnsdist.yml \
      -p opa-policies/ \
      --fail-on-warn \
      -o json > policy-results.json
```

## Policy Catalog

### Core (`dnsdist.rego`) — deny / warn

**Deny (blocks deployment):**
- Missing or empty backends list
- Missing backend address or protocol
- Health check mode "up" (bypasses monitoring)
- Invalid backend weight or max_in_flight
- Missing bind listen_address or protocol
- Open resolver detection (0.0.0.0 + no ACL)
- TLS binds without certificate/key
- Deprecated TLS versions (SSL3, TLS 1.0, 1.1)
- Weak/null/export/RC4 ciphers
- Console exposed without encryption or ACL
- Webserver without password, with weak config
- Wildcard ACL entries (0.0.0.0/0, ::/0)
- Invalid CIDR in ACLs
- Unnamed or incomplete query rules
- Allow-all query rules
- Running as root
- DNSCrypt without provider config
- Proxy protocol open to all

**Warn (advisory):**
- Single backend (no redundancy)
- No caching configured
- No dynamic rules (rate limiting)
- Unencrypted backend connections
- No webserver/monitoring
- No server_id
- All Do53 (no encrypted listeners)
- No external logging
- Single thread

### Compliance (`compliance.rego`) — violation

| Code | Category | Description |
|------|----------|-------------|
| ENCRYPT-01 | Encryption | No encrypted listener |
| ENCRYPT-02 | Encryption | No encrypted backend |
| ENCRYPT-03 | Encryption | No OCSP stapling |
| ACL-01 | Access Control | No ACL defined |
| ACL-02 | Access Control | Public range in ACL |
| ACL-03 | Access Control | No console ACL |
| ACL-04 | Access Control | No webserver ACL |
| AUTH-01 | Authentication | No console encryption key |
| AUTH-02 | Authentication | API without API key |
| AUTH-03 | Authentication | Webserver without password |
| LOG-01 | Audit Logging | No logging configured |
| LOG-02 | Audit Logging | Console logging disabled |
| PRIV-01..03 | Privileges | No setuid/setgid |
| ID-01..02 | Identification | No server_id |
| DNSSEC-01 | DNSSEC | Validation skipped |
| RATE-01 | Rate Limiting | No rate limiting |

### Hardening (`hardening.rego`) — finding

| Code | Category | Description |
|------|----------|-------------|
| HA-01..03 | Redundancy | Single backend, single AF, same subnet |
| PERF-01..07 | Performance | Threads, reuseport, sockets, cache size, TCP limits |
| DID-01..06 | Defense-in-Depth | Dynamic rules, Drop/TC actions, ECS, capabilities |
| MON-01..03 | Monitoring | Webserver, API, Carbon |
| LB-01..03 | Load Balancing | Policy choice, health check interval |

## Customization

Override specific rules by creating an override file:

```rego
# overrides.rego
package dnsdist

# Allow single backend in dev environments
deny := d if {
    d := {msg | msg := deny[_]; not contains(msg, "CRITICAL: Empty backends")}
}
```

Or use Conftest exceptions:

```yaml
# exceptions.yaml
- rules:
    - dnsdist
  msg: "ADVISORY: Only one backend"
```

## Example Test Run

```
$ conftest test example-dnsdist.yml -p .

WARN  - ADVISORY: Backend #0 (10.0.1.10:53) uses unencrypted Do53.
WARN  - ADVISORY: Backend #1 (10.0.1.11:53) uses unencrypted Do53.
WARN  - ADVISORY: No external logging (Carbon/dnstap) is configured.

3 warnings, 0 failures, 0 exceptions
```

## Requirements

- [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) >= 0.55 or [Conftest](https://www.conftest.dev/) >= 0.45
- dnsdist 2.x YAML configuration files

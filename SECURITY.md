# Security Policy

Maroon Elephant is a security tool; we hold ourselves to the bar we scan for.

## Reporting a vulnerability
Please report suspected vulnerabilities privately via GitHub Security Advisories on
`dibakshya01/maroon-elephant` (Security → Report a vulnerability). Do not open a public issue
for an unpatched vulnerability. We aim to acknowledge within 72 hours.

## Scope & posture
- The core runs locally and makes **no external calls** unless LLM enrichment is explicitly enabled.
- BYOK keys are never transmitted to any Maroon Elephant service and are never written to logs.
- Maroon Elephant scans itself in CI; the self-scan must be clean before release.

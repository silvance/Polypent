# Security Policy

PolyPent is a pentesting platform. The security posture of the platform
itself is in-scope for this policy; the security posture of systems users
test *with* PolyPent is not.

## Supported versions

PolyPent is pre-1.0. Only the `main` branch receives security fixes during
this period.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's
"Report a vulnerability" workflow on this repository. Do not file public
issues for security reports.

Include, where possible:

- a clear description of the issue and its impact
- reproduction steps or a proof of concept
- the affected version (commit SHA is fine)
- any suggested mitigation

We will acknowledge reports within 5 business days and aim to provide a
remediation plan within 30 days. Coordinated disclosure timelines are
negotiable for issues that require complex fixes.

## Out of scope

- Findings against software *tested by* PolyPent. Those belong in the
  affected vendor's disclosure channel.
- Reports that require a malicious operator with platform-level
  authorization (e.g. an admin token) to exploit, unless they cross a
  documented authorization boundary.
- Denial-of-service against a self-hosted deployment via resource
  exhaustion from a privileged caller.

## Threat model

A written threat model is tracked as a Phase 7 deliverable in
`docs/migration-plan.md`. Until then this policy is provisional.

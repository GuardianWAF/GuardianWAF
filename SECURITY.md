# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in GuardianWAF, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@guardianwaf.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

The following are in scope:
- WAF detection bypasses (payloads that should be blocked but aren't)
- Denial of service via crafted input
- Authentication bypass on the dashboard/API
- Information disclosure through error messages
- Memory safety issues

The following are out of scope:
- Attacks requiring physical access
- Social engineering
- Issues in dependencies (we have zero dependencies)

## Recognition

We appreciate responsible disclosure and will credit reporters in release notes (with permission).

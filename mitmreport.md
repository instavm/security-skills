---
description: Generate a security vulnerability report. Use when user asks for a report, summary of findings, or formatted vulnerability documentation.
---

# Generate Security Vulnerability Report

Generate a security report based on findings. Format: $ARGUMENTS (default: markdown)

## Report Template

```markdown
# Security Assessment Report

**Target**: [Application Name]
**Date**: [Assessment Date]
**Assessor**: [Name]

## Executive Summary

Brief overview of findings and overall security posture.

## Findings Summary

| # | Title | Severity | Status |
|---|-------|----------|--------|
| 1 | [Finding Title] | High | Open |

## Detailed Findings

### [APP] Finding Title
* **Severity**: `critical/high/medium/low/info`
* **Endpoint**: `https://example.com/api/endpoint`
* **Steps to Reproduce**:
  1. Step one
  2. Step two
  3. Verify with: `curl command here`
* **Impact**: Description of business/security impact
* **Remediation**: Specific steps to fix

## Severity Guidelines

- **CRITICAL**: RCE, full database access, admin takeover
- **HIGH**: Account takeover, payment bypass, mass data leak
- **MEDIUM**: PII leak, business logic bypass, limited data exposure
- **LOW**: Information disclosure, missing security headers
- **INFO**: Best practice violations, no direct impact

## Remediation Priorities

1. Critical and High - Immediate
2. Medium - Within 30 days
3. Low/Info - Next release cycle

## Testing Methodology

Description of tools and techniques used.
```

## Before Generating

Ask for:
- Target application name
- Findings to include (or analyze from log.txt)
- Output format preference (markdown/HTML/PDF outline)
- Include reproduction steps? (yes/no)

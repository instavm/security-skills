---
description: Find insecure configurations in HTTP traffic. Use when user asks about security headers, cookie security, CORS issues, or transport security.
---

# Find Insecure Configurations

Analyze the mitmproxy dump (log.txt) for insecure configs for: $ARGUMENTS

## Security Checks

### 1. HTTP Instead of HTTPS
- Sensitive data over plain HTTP
- Login/payment pages on HTTP
- Mixed content issues

### 2. Missing Security Headers
- `Strict-Transport-Security` (HSTS)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Content-Security-Policy`
- `X-XSS-Protection`
- `Referrer-Policy`

### 3. Insecure Cookies
- Missing `Secure` flag
- Missing `HttpOnly` flag
- Missing `SameSite` attribute
- Session cookies without protection

### 4. CORS Issues
- `Access-Control-Allow-Origin: *`
- Credentials allowed with wildcard
- Overly permissive origins

### 5. SSL/TLS Issues
- SHA1 certificates (deprecated)
- Weak cipher suites
- Outdated TLS versions

### 6. Information Disclosure
- Sensitive data in GET params
- Debug/verbose errors exposed
- Stack traces in responses
- Internal file paths revealed

## Output Format

For each finding:
- **Endpoint/Resource**: Where issue exists
- **Issue**: What's misconfigured
- **Current Value**: What was observed
- **Recommended**: Secure configuration
- **Risk**: Potential attack vector
- **Severity**: Critical/High/Medium/Low/Info

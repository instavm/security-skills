---
description: Comprehensive security audit of mitmproxy traffic. Use when user wants to analyze captured HTTP traffic for vulnerabilities, or mentions pentesting, security testing, or vulnerability assessment.
---

# Security Audit of Captured Traffic

Perform a comprehensive security audit of the mitmproxy dump (log.txt) for: $ARGUMENTS

## Audit Checklist

Run these checks systematically:

### 1. Reconnaissance
- [ ] List all unique domains/subdomains seen
- [ ] List all API endpoints with methods
- [ ] Identify API patterns (REST, GraphQL, etc.)

### 2. Authentication & Session
- [ ] Check for missing authentication on sensitive endpoints
- [ ] Look for session tokens in URLs or GET params
- [ ] Check cookie security flags (Secure, HttpOnly, SameSite)
- [ ] Identify predictable session/token patterns

### 3. Authorization (IDOR)
- [ ] Find sequential/enumerable IDs in URLs
- [ ] Check for base64 encoded IDs (easy to decode/iterate)
- [ ] Look for user IDs, order IDs, transaction IDs
- [ ] Test if one user's token works for another's resources

### 4. Data Exposure
- [ ] PII in responses (email, phone, address)
- [ ] Partial/full credit card numbers
- [ ] Passwords or hashes in responses
- [ ] Internal IPs, file paths, stack traces

### 5. Secrets & Keys
- [ ] API keys in requests/responses
- [ ] Hardcoded tokens or salts
- [ ] Cloud credentials (AWS, GCP, Azure)
- [ ] Third-party service keys

### 6. Payment Security
- [ ] Checksum/hash validation on callbacks
- [ ] Amount manipulation possibilities
- [ ] Status parameter tampering
- [ ] Signature collision vulnerabilities

### 7. Input Validation
- [ ] OTP in response (should only be sent via SMS/email)
- [ ] Rate limiting on sensitive endpoints
- [ ] Enumerable endpoints without protection

### 8. Transport Security
- [ ] HTTP instead of HTTPS for sensitive data
- [ ] Missing security headers
- [ ] Referer leakage to third parties

## Output Format

For each finding, provide:
- **Endpoint**: The vulnerable URL/API
- **Vulnerability**: Type of issue
- **Evidence**: What was found in the traffic
- **Severity**: Critical/High/Medium/Low/Info
- **Recommendation**: How to fix

Prioritize findings by severity and exploitability.

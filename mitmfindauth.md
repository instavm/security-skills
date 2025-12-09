---
description: Find authentication and session vulnerabilities. Use when user asks about auth bypass, session issues, login security, or token problems.
---

# Find Authentication Vulnerabilities

Analyze the mitmproxy dump (log.txt) for auth issues for: $ARGUMENTS

## High-Value Auth Patterns (from 783 real HackerOne bounty reports)

### 1. Password Reset Token Issues
**Real examples from bounties:**
- Reset link not expiring after email change
- Reset token reusable multiple times
- Reset token valid after password change
- Predictable/sequential reset tokens

**Search patterns:**
```bash
grep -iE '(reset|forgot|recover|password).*token' log.txt
grep -iE 'token=[a-zA-Z0-9]{10,}' log.txt
```

### 2. Privilege Escalation via Role Manipulation
**Real examples:**
- Change `role=user` to `role=admin` in request
- Modify `isAdmin=false` to `isAdmin=true`
- Access admin endpoints with user token
- Send invites on behalf of other admins

**Search patterns:**
```bash
grep -iE '(role|permission|privilege|isAdmin|is_admin|user_type|account_type)[=:]["'\'']?\w+' log.txt
```

### 3. Comment/Action After Disable
**Real examples:**
- Edit comments after comments disabled on video
- Perform actions after account suspended
- Access resources after permission revoked

**Search patterns:**
```bash
grep -iE '(edit|update|delete|modify).*comment' log.txt
grep -iE 'action=(edit|delete|update)' log.txt
```

### 4. File/Resource Access Control
**Real examples:**
- Private file becomes public via transformation
- Access invoice documents without authorization
- Download private attachments with predictable URLs

**Search patterns:**
```bash
grep -iE '(download|file|document|attachment|invoice|receipt)' log.txt
grep -iE '\.(pdf|doc|xlsx?|csv)' log.txt
```

### 5. Session/Token Vulnerabilities
**Patterns to check:**
```
- Session token in URL (session_id=xxx in query params)
- JWT with weak/no signature (alg: none attack)
- Token doesn't change after password change
- Token valid after logout
- Predictable session tokens
```

**Search patterns:**
```bash
grep -iE 'session[_-]?(id|token)=' log.txt
grep -oE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*' log.txt  # JWT
```

## Vulnerability Categories & Severity

| Category | Severity | What to Look For |
|----------|----------|------------------|
| Admin access without auth | **CRITICAL** | Admin endpoints returning 200 without token |
| Password reset token abuse | **HIGH** | Tokens that don't expire/invalidate |
| Privilege escalation | **HIGH** | Role params that can be modified |
| Session fixation | **HIGH** | Session ID in URL, unchanging tokens |
| Missing auth on sensitive endpoints | **HIGH** | PII/financial data without auth |
| IDOR via auth context | **MEDIUM** | Actions performed as different user |
| Weak token entropy | **MEDIUM** | Short or predictable tokens |
| Auth bypass via response manipulation | **MEDIUM** | Client-side auth checks |

## Testing Methodology

### Step 1: Map Authentication Flows
```bash
# Find login/auth endpoints
grep -iE '(login|signin|authenticate|oauth|token|session)' log.txt

# Find logout endpoints
grep -iE '(logout|signout|revoke)' log.txt

# Find password flows
grep -iE '(password|reset|forgot|recover|change)' log.txt
```

### Step 2: Analyze Token Structure
```bash
# Extract bearer tokens
grep -oE 'Bearer [a-zA-Z0-9._-]+' log.txt | sort -u

# Extract cookies
grep -oE 'Cookie:.*' log.txt | head -20

# Check for JWT
grep -oE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+' log.txt
```

### Step 3: Test Token Validity
```bash
# Test if token works after logout (replay attack)
curl -H "Authorization: Bearer OLD_TOKEN" "https://target.com/api/profile"

# Test with modified role
curl -X POST "https://target.com/api/update" -d '{"role":"admin"}'

# Test admin endpoint with user token
curl -H "Authorization: Bearer USER_TOKEN" "https://target.com/api/admin/users"
```

### Step 4: Check Password Reset Flow
```bash
# Test reset token reuse
curl "https://target.com/reset?token=USED_TOKEN"

# Test reset token after email change
# (token from old email should be invalid)
```

## Real Attack Scenarios

### Scenario 1: Account Takeover via Reset Token
```
1. Attacker requests password reset for victim
2. Victim changes email before using reset link
3. Old reset link still works → Attacker takes over account
```

### Scenario 2: Privilege Escalation via Request Manipulation
```
1. User captures their profile update request
2. Adds "role": "admin" or "isAdmin": true
3. Server doesn't validate, grants admin access
```

### Scenario 3: BOLA via Action Replay
```
1. User A creates comment on their post
2. User B captures edit request: POST /edit_comment?id=123
3. User B replays with different comment_id → edits User A's comment
```

## Output Format

```
## AUTH Finding: [Brief Description]

**Endpoint**: `METHOD https://target.com/path`
**Type**: [Password Reset|Privilege Escalation|Session|Access Control]
**Severity**: [CRITICAL|HIGH|MEDIUM|LOW]

**Vulnerable Flow**:
1. Step one
2. Step two
3. Exploit step

**Evidence**:
[Request/response snippets]

**Impact**:
- Account takeover
- Unauthorized access
- Data exposure

**Test Command**:
curl -X METHOD 'https://target.com/...' -H '...'

**Remediation**:
- Invalidate tokens on sensitive actions
- Server-side role validation
- Rate limit sensitive endpoints
```

## False Positives to Ignore

- Public endpoints that are intentionally unauthenticated
- Read-only public data endpoints
- Health check / status endpoints
- Static asset endpoints
- Endpoints that return generic errors for invalid tokens

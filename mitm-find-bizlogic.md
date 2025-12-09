---
description: Find Business Logic vulnerabilities in captured traffic. Use when user asks about payment bypass, race conditions, workflow abuse, or application logic flaws.
---

# Find Business Logic Vulnerabilities

Analyze the mitmproxy dump (log.txt) for business logic flaws for: $ARGUMENTS

## High-Value Business Logic Patterns (from 376 real HackerOne bounty reports)

### 1. Payment/Pricing Manipulation
**Real examples from bounties:**
- Uber: paymentProfileUUID bypass for free rides
- Negative quantity for refund abuse
- Price manipulation in cart
- Coupon/promo code stacking
- Currency conversion abuse

**Search patterns:**
```bash
grep -iE '(price|amount|total|cost|fee|discount|coupon|promo|payment)' log.txt
grep -iE '(quantity|qty|count|num)[=:]["'\'']?-?[0-9]+' log.txt
```

### 2. Account/Email Verification Bypass
**Real examples:**
- Acronis: Account takeover via unverified email change
- Email change without verification
- Phone verification bypass
- Account deletion incomplete

**Search patterns:**
```bash
grep -iE '(verify|confirm|validate|activate|email|phone)' log.txt
grep -iE '(change|update).*(email|phone|password)' log.txt
```

### 3. Rate Limit/Brute Force Bypass
**Real examples:**
- No rate limiting on OTP verification
- Bypassing login attempt limits
- Parallel request exploitation
- CAPTCHA bypass via API

**Search patterns:**
```bash
grep -iE '(otp|code|pin|token|verify)' log.txt
grep -iE '(limit|rate|attempts|retry|captcha)' log.txt
```

### 4. Race Conditions
**Real examples:**
- Double-spending in wallet
- Concurrent coupon redemption
- Parallel transfer requests
- Vote manipulation via racing

**Look for:**
```
- Financial transactions (transfer, payment, redeem)
- Limited resource operations (claim, reserve, book)
- State-changing operations (status update, approve)
```

### 5. Workflow/State Bypass
**Real examples:**
- Skip steps in multi-step process
- Access feature without subscription
- Bypass approval workflow
- Manipulate exam/quiz results

**Search patterns:**
```bash
grep -iE '(step|stage|phase|status|state|workflow|approve)' log.txt
grep -iE '(submit|complete|finish|process)' log.txt
```

## Vulnerability Categories & Severity

| Type | Severity | Impact |
|------|----------|--------|
| Payment bypass/manipulation | **CRITICAL** | Financial loss |
| Account takeover via logic flaw | **CRITICAL** | Full account compromise |
| Privilege escalation via workflow | **HIGH** | Unauthorized access |
| Free premium features | **HIGH** | Revenue loss |
| Data manipulation | **MEDIUM** | Integrity issues |
| Rate limit bypass | **MEDIUM** | Abuse potential |
| Information disclosure via logic | **LOW** | Privacy leak |

## Testing Methodology

### Step 1: Map Business Flows
```bash
# Find transaction-related endpoints
grep -iE 'POST.*(order|payment|checkout|cart|purchase|subscribe|redeem)' log.txt

# Find state-changing endpoints
grep -iE 'POST.*(update|change|modify|set|create|delete)' log.txt

# Find verification flows
grep -iE '(verify|confirm|validate|check|otp|code)' log.txt
```

### Step 2: Test Parameter Manipulation
```bash
# Price manipulation
# Original: {"price": 100, "quantity": 1}
# Test: {"price": 1, "quantity": 1}
# Test: {"price": 100, "quantity": -1}

# Status manipulation
# Original: {"status": "pending"}
# Test: {"status": "approved"}

# Role manipulation
# Original: {"plan": "free"}
# Test: {"plan": "premium"}
```

### Step 3: Test Race Conditions
```bash
# Send concurrent requests
for i in {1..10}; do
  curl -X POST 'https://target.com/api/redeem' -d '{"code":"PROMO123"}' &
done
wait

# Check if code was redeemed multiple times
```

### Step 4: Test Workflow Bypass
```bash
# Skip step 2, go directly to step 3
curl 'https://target.com/api/checkout/step3' -d '{"order_id":"123"}'

# Access premium without subscription
curl 'https://target.com/api/premium/feature' -H 'Cookie: free_user_session'
```

## Real Attack Scenarios

### Scenario 1: Free Rides via Payment Profile Bypass
```
1. Capture ride request with paymentProfileUUID
2. Remove or modify paymentProfileUUID field
3. Server doesn't validate, processes ride without payment
4. Unlimited free rides
```

### Scenario 2: Account Takeover via Email Change
```
1. Victim signs up with email but doesn't verify
2. Attacker changes email via API (no verification required)
3. Attacker now controls account with their email
4. Reset password → full takeover
```

### Scenario 3: Coupon Race Condition
```
1. Find single-use coupon worth $100
2. Send 10 concurrent redeem requests
3. Race condition allows multiple redemptions
4. Get $1000 discount instead of $100
```

### Scenario 4: Exam Score Manipulation
```
1. Take online exam, submit answers
2. Intercept response with score
3. Find score calculation endpoint
4. Replay with modified answers or directly set score
```

## Parameters to Manipulate

### Financial Parameters
```
price, amount, total, subtotal, tax
discount, discount_percent, coupon_value
quantity, qty, count, num
currency, currency_code
payment_method, payment_id
tip, fee, shipping_cost
```

### Status/State Parameters
```
status, state, phase, step
is_verified, is_active, is_premium
approved, confirmed, completed
role, plan, tier, subscription
```

### Identity Parameters
```
user_id, account_id, profile_id
email, phone, username
referral_code, invite_code
```

## Output Format

```
## Business Logic Finding: [Brief Description]

**Endpoint**: `METHOD https://target.com/path`
**Flow**: [Payment|Registration|Verification|Workflow]
**Severity**: [CRITICAL|HIGH|MEDIUM|LOW]

**Normal Flow**:
1. User does X
2. Server validates Y
3. Action Z occurs

**Exploit Flow**:
1. User does X
2. User manipulates [parameter]
3. Server fails to validate
4. Unauthorized action occurs

**Evidence**:
[Request/response showing manipulation]

**Impact**:
- Financial loss of $X per abuse
- Account compromise
- Unauthorized access to premium features

**Test Command**:
curl -X POST 'https://target.com/...' -d '{"manipulated":"value"}'

**Remediation**:
- Server-side validation of all parameters
- Signed/encrypted values for sensitive data
- Idempotency keys for financial operations
- Rate limiting on sensitive endpoints
```

## False Positives to Ignore

- Client-side only calculations (validated server-side)
- Parameters that return error when manipulated
- Debug/test endpoints in non-production
- Rate limits that are intentionally lenient
- Features that are intentionally free/accessible

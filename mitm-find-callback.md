---
description: Find payment callback and webhook vulnerabilities. Use when user asks about payment security, callback tampering, hash validation, or transaction manipulation.
---

# Find Payment Callback Vulnerabilities

Analyze the mitmproxy dump (log.txt) for payment callback issues for: $ARGUMENTS

## Vulnerability Types

### 1. Hash/Signature Not Validated
- Callback accepts any hash value
- Hash parameter present but not verified
- Can change status without valid signature

### 2. Status Manipulation
- Change `status=failed` to `status=success`
- Modify `unmappedstatus` parameter
- Tamper with transaction result

### 3. Amount Manipulation
- Modify amount before callback
- Pay less, get full order
- Decimal manipulation

### 4. Signature Collision
- Same signature works for payment and refund
- Parameter reordering gives same hash
- Missing fields in signature calculation

### 5. Checksum Generation Exposed
- API returns checksum even on error
- Can generate arbitrary checksums
- Checksum algorithm is weak (MD5/SHA1 without salt)

## Testing Approach

```bash
# Test callback with modified status
curl -X POST "https://merchant.com/payment/callback" \
  -d "txnid=12345&status=success&hash=original_hash"

# Test with invalid hash
curl -X POST "https://merchant.com/payment/callback" \
  -d "txnid=12345&status=success&hash=aaaa"
```

## Red Flags in Traffic

- Callback URLs with all params in request
- Hash visible in client-side code
- Salt/secret in JavaScript
- Error responses containing valid checksums

## Output Format

For each finding:
- **Callback URL**: Vulnerable endpoint
- **Issue**: What can be manipulated
- **Parameters**: Affected fields
- **Test**: How to exploit
- **Impact**: Free orders, refunds, etc.
- **Fix**: Proper server-side validation

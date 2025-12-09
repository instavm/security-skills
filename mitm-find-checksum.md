---
description: Find checksum and signature vulnerabilities. Use when user asks about hash validation, signature bypass, checksum manipulation, or cryptographic weaknesses.
---

# Find Checksum/Signature Vulnerabilities

Analyze the mitmproxy dump (log.txt) for checksum issues for: $ARGUMENTS

## Vulnerability Types

### 1. Checksum Generation Exposed
- API returns hash even on error
- Can generate arbitrary checksums
- Checksum endpoint accessible without auth

### 2. Weak Algorithms
- MD5 without salt
- SHA1 (deprecated)
- Simple concatenation

### 3. Signature Collision
- Same signature for different operations
- Payment and refund use same algorithm
- Parameter reordering gives same hash

### 4. Missing Fields in Checksum
- Amount not in checksum calculation
- Status not included
- Critical fields missing

### 5. Checksum Not Validated
- Hash parameter present but ignored
- Backend accepts any hash value
- Validation only on specific endpoints

## Patterns to Find

```
# Look for hash/checksum parameters
hash=, checksum=, signature=, sign=, hmac=

# Look for checksum generation APIs
/generateHash, /getChecksum, /createSignature

# Error responses with valid checksums
"error": "...", "checksum": "valid_hash"
```

## Testing Approach

```bash
# Test if checksum is validated
curl -X POST "https://target.com/callback" \
  -d "amount=100&status=success&hash=invalid"

# Test checksum generation
curl "https://target.com/api/generateChecksum" \
  -d "amount=1&status=success"
```

## Output Format

For each finding:
- **Endpoint**: Where checksum is used
- **Issue**: Type of vulnerability
- **Algorithm**: If identifiable
- **Fields Included**: What's in the hash
- **Exploit**: How to bypass/generate
- **Impact**: Payment fraud, data tampering
- **Fix**: Strong HMAC, include all fields

---
description: Find enumerable endpoints that leak data through iteration. Use when user asks about data scraping, bulk data access, or iterating through records.
---

# Find Enumerable Endpoints

Analyze the mitmproxy dump (log.txt) for enumerable endpoints for: $ARGUMENTS

## What Makes an Endpoint Enumerable

### 1. Sequential IDs
- `/api/user/1`, `/api/user/2`, `/api/user/3`
- `/order/100001`, `/order/100002`
- `/transaction/TXN00001`

### 2. Predictable Patterns
- Date-based: `/report/2024-01-01`
- Timestamp: `/log/1704067200`
- Simple increments in any parameter

### 3. Weak Encoding
- Base64 numbers: `/profile/MTIzNDU=` (12345)
- Hex: `/data/0x1A2B`
- URL-safe base64

### 4. No Pagination Limits
- `/api/users?limit=999999`
- `/search?count=all`

## Testing Commands

```bash
# Sequential iteration
for i in {1..100}; do
  curl -s "https://target.com/api/resource/$i" >> output.json
  sleep 0.5
done

# Base64 iteration
for i in {1000..1100}; do
  id=$(echo -n $i | base64)
  curl -s "https://target.com/api/resource/$id"
done

# Date iteration
for d in {01..31}; do
  curl -s "https://target.com/api/report/2024-01-$d"
done
```

## Output Format

For each finding:
- **Endpoint**: URL pattern
- **Parameter**: What can be iterated
- **Pattern**: Sequential/Base64/Date/etc.
- **Sample Range**: Observed values
- **Data Exposed**: What each iteration reveals
- **Bulk Test**: curl command for mass extraction
- **Fix**: Use UUIDs, add auth, rate limit

---
description: Find IDOR (Insecure Direct Object Reference) vulnerabilities in captured traffic. Use when user asks about authorization issues, sequential IDs, or accessing other users' data.
---

# Find IDOR Vulnerabilities

Analyze the mitmproxy dump (log.txt) for IDOR vulnerabilities for: $ARGUMENTS

## High-Value IDOR Patterns (from 132 real HackerOne bounty reports)

### 1. User/Account Object References
```
user_id, userId, user-id, uid, account_id, accountId
customer_id, customerId, member_id, memberId
profile_id, owner_id, creator_id, author_id
```
**Real example**: `https://zomato.com/gold/payment-success?subscription_id=XXX&user_id=YYY`

### 2. Resource Object References
```
order_id, orderId, booking_id, bookingId, reservation_id
transaction_id, txn_id, payment_id, invoice_id
document_id, doc_id, file_id, attachment_id
report_id, ticket_id, case_id, issue_id
```
**Real example**: `/api/shopify/orders/{order_id}` - change order_id to access other orders

### 3. Organizational Object References
```
project_id, projectId, team_id, teamId, group_id, groupId
workspace_id, org_id, organization_id, company_id
board_id, channel_id, room_id, space_id
```
**Real example**: `PUT /boards/{board_id}.json` - GitLab private project label access

### 4. Content Object References
```
media_code, media_id, image_id, video_id, asset_id
post_id, postId, comment_id, message_id, thread_id
article_id, content_id, item_id, entry_id
```
**Real example**: `media_code=2013124` - sequential IDs expose other users' media

### 5. Session/Token References (High Impact)
```
session_id, sessionId, subscription_id, subscriptionId
card_id, cardId, fuel_card_id, membership_id
api_key_id, token_id, credential_id
```
**Real example**: `activateFuelCard?id=XXX` - Uber driver UUID enumeration

## ID Encoding Patterns to Decode

| Pattern | Example | Decode Method |
|---------|---------|---------------|
| Base64 numeric | `MTIzNDU2` | `echo MTIzNDU2 \| base64 -d` → 123456 |
| Hex | `0x1E240` | Convert to decimal → 123456 |
| UUID v1 | Contains timestamp | Extract timestamp component |
| Short hash | `a1b2c3` | May be truncated MD5 of sequential |
| Padded | `000012345` | Strip padding, increment |

## Where to Find IDORs

### URL Path Parameters (Most Common)
```
/api/v1/users/{id}/profile
/api/v1/orders/{id}/details
/api/v1/documents/{id}/download
/campaign-manager-api/accounts/{id}
```

### Query Parameters
```
?user_id=12345&action=view
?subscription_id=XXX&user_id=YYY
?media_code=2013124
```

### Request Body (JSON/Form)
```json
{"user_id": 12345, "action": "delete"}
{"board": {"id": 857058, "labels": [{"id": 123}]}}
```

### Headers (Rare but High Impact)
```
X-User-Id: 12345
X-Account-Id: 67890
```

## Severity Rating

| Access Type | Severity | Example |
|-------------|----------|---------|
| Read other users' PII | **CRITICAL** | View email, phone, address |
| Modify other users' data | **HIGH** | Edit profile, delete content |
| Access other users' orders/transactions | **HIGH** | View order history, payment info |
| Read other users' private content | **MEDIUM** | View private posts, documents |
| Enumerate user existence | **LOW** | Confirm if user_id exists |
| Access public-ish data | **INFO** | View subscription dates |

## Testing Methodology

### Step 1: Identify Candidate Parameters
Search for ID patterns in traffic:
```bash
grep -iE '(user|account|order|session|subscription|member|card|document|file|project|team|group)[-_]?id' log.txt
```

### Step 2: Check for Sequential/Predictable IDs
```bash
# Extract numeric IDs and check if sequential
grep -oE 'id[=:]["'\'']?[0-9]+' log.txt | sort -u
```

### Step 3: Test Authorization
```bash
# Test with ID ± 1
curl -H "Cookie: victim_session" "https://target.com/api/resource/12345"
curl -H "Cookie: victim_session" "https://target.com/api/resource/12344"  # Another user's
```

### Step 4: Verify Impact
- Does response contain different user's data?
- Can you perform actions (edit/delete) on other user's resources?
- What sensitive fields are exposed?

## Output Format

For each finding report:

```
## IDOR Finding: [Brief Description]

**Endpoint**: `METHOD https://target.com/path`
**Parameter**: `param_name` in [path|query|body]
**ID Type**: [Sequential|Base64|UUID|Hash]
**Current Value**: `12345`
**Severity**: [CRITICAL|HIGH|MEDIUM|LOW]

**Evidence**:
[Show request/response snippets]

**Impact**:
- What data is exposed
- What actions can be performed

**Test Command**:
curl -X METHOD 'https://target.com/...' -H 'Cookie: ...'

**Remediation**:
- Implement proper authorization checks
- Use indirect references (mapping table)
- Validate user owns the resource
```

## False Positives to Ignore

- Analytics/tracking endpoints (write-only, no data returned)
- Public content IDs (movie IDs, product catalog)
- Resource IDs that return same data regardless of auth
- IDs that require valid session AND return 403 for wrong user

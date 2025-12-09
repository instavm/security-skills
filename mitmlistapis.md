---
description: List all APIs from mitmproxy traffic capture. Use when user asks to see APIs, endpoints, or wants an overview of captured HTTP traffic for a website or app.
---

# List APIs from Traffic Capture

Analyze the mitmproxy dump (log.txt) and list all APIs for: $ARGUMENTS

## Instructions

1. Search log.txt for the target domain/app
2. Extract unique API endpoints
3. Group by functionality (auth, user, payment, etc.)

## Output Format

For each API found:
- **Method**: GET/POST/PUT/DELETE
- **Endpoint**: `/api/path` (skip domain)
- **Input params**: Query params or body fields
- **Response fields**: Key fields returned (concise)

## Grouping Suggestions
- Authentication (login, register, OTP, token)
- User Profile (profile, settings, preferences)
- Transactions (orders, payments, history)
- Content (products, listings, search)
- Admin/Internal (if any found)

If no website specified, ask which one to analyze.

# DAT250 SecureApp Smoke Test

Use this quick check after `docker compose up --build -d` or after a reset.

## 1) Service status

```bash
docker compose ps
```

Expected: `nginx`, `backend`, `db`, `mailhog`, `phppgadmin` are `Up`.

## 2) HTTP endpoint checks

```bash
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost:18443/
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8025/
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/
curl -k -s https://localhost:18443/health
```

Expected:
- `18443` returns `200` (`18181` redirects to HTTPS with `301`)
- `8025` returns `200`
- `8081` returns `200`
- `/health` returns `{"status":"ok"}`

## 3) Seeded login + dashboard

```bash
curl -k -s -c /tmp/dat250.cookies \
  -d "email=alice@student.uis.no&password=Alice123" \
  -X POST -D /tmp/dat250_login_headers.txt \
  -o /tmp/dat250_login_body.html \
  https://localhost:18443/login

curl -k -s -b /tmp/dat250.cookies \
  -D /tmp/dat250_dashboard_headers.txt \
  -o /tmp/dat250_dashboard_body.html \
  https://localhost:18443/dashboard
```

Expected:
- Login returns `302` to `/dashboard`
- Dashboard returns `200`
- Dashboard page contains `Dashboard` and `Welcome,`

## 4) Password reset + MailHog

```bash
curl -k -s -d "email=alice@student.uis.no" \
  -X POST https://localhost:18443/reset-password \
  -o /tmp/dat250_reset_response.html

curl -s http://localhost:8025/api/v2/messages
```

Expected:
- At least one message exists in MailHog API output
- Message for `alice@student.uis.no` contains a reset link path like `/reset-password/<token>`

## 5) Optional DB GUI check

Open `http://localhost:8081` and use:
- Username: `dat250`
- Password: `dat250`

Expected: successful login to PostgreSQL server view.

## 6) Selected security regression coverage

Run the isolated automated suite using the commands in
[the README](../README.md#security-regression-tests).
The suite uses FastAPI's HTTP test client, real PostgreSQL, and a mocked email
sender. No application or database ports are published by the test configuration.

| Area | Expected result |
|---|---|
| Grade ownership | Alice and Bob can read their own grades; another student's or a nonexistent grade redirects to `/grades`. Anonymous access redirects to login. This protection predates this remediation. |
| Stored comment XSS | New and previously stored HTML/script comments render as escaped text. Comments are still stored and displayed. |
| Course search SQL injection | Quotes and SQL fragments are treated as search data, with no database error or expanded results. Case-insensitive partial and empty searches still work. |
| User administration | Only the database-backed `admin` role can list/search users or change roles. Students, teachers and TAs receive 403, even with a forged `x-role` header. Anonymous requests redirect to login. Invalid target roles receive 400 without changing data. |
| Password reset | A 32-byte cryptographically random token is emailed; only its SHA-256 digest is stored. Links expire after 15 minutes, are replaced by a new request, and can succeed only once, including concurrent submissions. Successful reset invalidates that user's existing sessions, changes only that account, and the new password works for login. |
| Reset abuse protection | The response text/status does not distinguish registered from unknown email addresses. Limits persist in PostgreSQL: 3 requests per email and 20 per observed peer per 15 minutes; 10 token-page visits/submissions per observed peer per 15 minutes. Excess requests return 429 with `Retry-After`. Forged forwarding headers are not used by application code to choose a quota bucket. |
| Reset migration | The migration can be reapplied and invalidates legacy links without deleting accounts. Reapplying it also invalidates any newer links. |
| Error handling | Database exceptions produce generic HTTP 500 responses rather than debug tracebacks. The server still reports unexpected errors. |

Reset responses disable caching and referrer transmission. Live tokens are not
printed by the email sender. Uvicorn access logging is disabled, and nginx skips
access-log entries for token URLs. Keep MailHog private: its inbox intentionally
contains the live reset links. Do not copy tokens or passwords into reports.

Quotas use the peer identity supplied by the ASGI server, not arbitrary request
headers. Without a trusted reverse-proxy configuration, clients behind nginx may
share the peer quota. This is intentionally conservative for this local-only lab.
Expired quota rows can be pruned with:

```sql
DELETE FROM password_reset_limits
WHERE window_start < NOW() - INTERVAL '1 day';
```

The suite does not claim to fix profile access, grading-administration access,
SSRF, password hashing, session-cookie settings, or other unselected lab flaws.
It is not a substitute for the original Assignment 1 evidence or browser-level
retest screenshots required by the course report.

### Verification performed on 2026-11-16

- Fresh isolated PostgreSQL initialization and all 21 regression tests passed
  (test-process exit code 0).
- Five browser flows passed against an isolated nginx/backend/PostgreSQL/MailHog
  stack: grade ownership; escaped comments and safe search; denied student
  administration and successful administrator role changes; real SMTP delivery;
  and password reset with old/new login checks and rejection of a reused link.
- The browser displayed stored script/image payloads as literal text, without
  executable comment elements or JavaScript dialogs.
- nginx configuration validation, both Compose configurations, and Git whitespace
  validation passed.
- All test data and services were isolated from the normal lab deployment.

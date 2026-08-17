# SentraX AI — VulnMart Target Spec

This replaces `juice-shop-targets.md`. This is the ground truth for Phase 0a and Phase 4 (`implementation-plan.md`), matched exactly to `custom-target-build-prompt.md` — the spec your friend's coding agent is building from. Because you control both sides (the bugs planted and the tool that finds them), this doc can be written before the app exists and just needs a quick confirm once it's built, instead of another exploration hunt.

**Still do the Phase 0a confirm step** — have your friend verify all 3 bugs work as described before handing the app back, and re-confirm yourself once you have it running. Update this doc if anything ends up built slightly differently than specified.

---

## 1. SQL Injection — Login bypass

- **Endpoint:** `POST /api/login`
- **Fields:** `email`, `password`
- **Payload:** `' OR 1=1--` in the `email` field, anything in `password`
- **Why it works:** the login query concatenates raw input into a SQL string instead of parameterizing it
- **Confirmed** = login succeeds (200 / session set / token issued) with no real credentials
- **Not confirmed** = normal login failure (401 or equivalent)

---

## 2. XSS — Stored, via product reviews

- **Endpoint:** `POST /api/reviews`, reflected back on `GET /reviews`
- **Payload:** `<script>alert('sentrax')</script>` submitted as review text
- **Why it works:** saved reviews are rendered back into the page without escaping
- **Confirmed** = after submitting, fetching `/reviews` returns the payload **unescaped** in the response — `<script>` appears literally, not as `&lt;script&gt;`
- **Not confirmed** = payload appears HTML-escaped or stripped

---

## 3. IDOR — Order access

- **Endpoint:** `GET /api/order/<id>`
- **Technique:** log in as Alice (`alice@vulnmart.test` / `alice123`, Order ID 1), then request `/api/order/2` (Bob's order) while still authenticated as Alice
- **Why it works:** the endpoint returns whatever order ID is requested, without checking ownership
- **Confirmed** = response returns Bob's order details (different product/buyer email than Alice's own order) while authenticated as Alice
- **Not confirmed** = 401/403, or it silently returns Alice's own order regardless of ID requested

---

## 4. Broken Authentication — No login rate limiting

- **Endpoint:** `POST /api/login`
- **Technique:** send 10-20 consecutive failed login attempts against the same account (e.g. `alice@vulnmart.test` with a wrong password) in quick succession
- **Confirmed** = all attempts return the same immediate failure response, no delay/lockout/CAPTCHA introduced
- **Not confirmed** = requests get throttled or blocked after some threshold

---

## Quick reference table

| Vuln | Endpoint | Method | Payload/Technique |
|---|---|---|---|
| SQLi | `/api/login` | POST | `' OR 1=1--` in email field |
| XSS | `/api/reviews` → `/reviews` | POST then GET | `<script>alert('sentrax')</script>` as review text |
| IDOR | `/api/order/<id>` | GET | Login as Alice (order 1), request order 2 (Bob's) |
| Broken Auth | `/api/login` | POST | 10-20 rapid failed attempts, same account |

## Seed accounts (from `custom-target-build-prompt.md`)

| User | Email | Password | Order ID |
|---|---|---|---|
| Alice | alice@vulnmart.test | alice123 | 1 |
| Bob | bob@vulnmart.test | bob123 | 2 |

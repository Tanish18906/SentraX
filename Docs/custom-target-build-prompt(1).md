# Prompt for coding agent: build a small, deliberately vulnerable web app

Copy everything below into your coding agent (Antigravity, Claude Code, Cursor, whatever you're using) as-is.

---

## What to build

A small web app called **"VulnMart"** — a tiny fake online store, built with **known, deliberate security bugs** for use as a test target by a separate security-testing tool. This is not a real product — it exists purely to be attacked by another program during a demo. Correctness of the bugs matters more than how polished it looks.

**Stack:** Node.js + Express backend, SQLite database, plain HTML/CSS/vanilla JS frontend (no framework needed — keep it simple). Runs locally on `http://localhost:4000`.

**Setup requirement:** must run with just `npm install && npm start`, no other config needed, no Docker required. Seed the database with at least 2 fake users on startup automatically (see below).

---

## Pages and deliberate bugs (build exactly these three)

### 1. Login page — `/login`
- Simple form: email + password fields, submit button
- Backend endpoint: `POST /api/login`
- **Deliberate bug (SQL Injection):** build the database query by directly concatenating the raw email/password input into a SQL string — do NOT use parameterized queries or an ORM's safe query builder. Example of the *vulnerable* pattern to actually implement:
  ```js
  const query = `SELECT * FROM users WHERE email='${email}' AND password='${password}'`;
  db.get(query, (err, row) => { ... });
  ```
- **Deliberate bug (Broken Authentication):** do NOT add any rate-limiting, attempt counting, delay, or lockout on this endpoint — repeated failed attempts should behave identically every time, no matter how many in a row.
- On successful login (real credentials or successful SQLi bypass), set a simple session/cookie or return a token, and redirect/respond as "logged in."

### 2. Product reviews page — `/reviews`
- A page showing a product with a list of reviews, and a form to submit a new review (just a text box + submit)
- Backend endpoint: `POST /api/reviews` (saves the review), and the page displays saved reviews
- **Deliberate bug (XSS):** when rendering a saved review back onto the page, insert it directly into the HTML without escaping — e.g. using `innerHTML` on the frontend, or directly interpolating the raw review text into a server-rendered template without an escaping/sanitization step. A review containing `<script>alert('vulnmart')</script>` should actually execute when the page loads and displays it.

### 3. Order details page — `/order/:id`
- After logging in, a simple page at a URL like `/order/3` showing that order's details (product name, price, buyer email)
- Backend endpoint: `GET /api/order/:id`
- **Deliberate bug (IDOR):** the backend should look up and return whatever order ID is requested in the URL, without checking whether that order actually belongs to the currently logged-in user. Any logged-in user should be able to view any order by just changing the number in the URL.

---

## Seed data (required, so the bugs are demonstrable)

On first run, auto-create:
- **User A:** `alice@vulnmart.test` / password `alice123`, with **Order ID 1** (any fake product, e.g. "Wireless Mouse", $19.99)
- **User B:** `bob@vulnmart.test` / password `bob123`, with **Order ID 2** (a different fake product, e.g. "Desk Lamp", $34.99)

This is what makes the IDOR bug demonstrable — logging in as Alice and requesting `/order/2` should show Bob's order.

---

## What NOT to do

- No real security measures anywhere — no input sanitization, no parameterized queries, no CSRF protection, no rate limiting. The whole point is that it's broken.
- Don't add extra pages, extra features, or extra polish beyond what's listed above — keep the surface area small and exactly matched to these 3 bugs, nothing more.
- Don't deploy this anywhere public — it only ever runs on `localhost`.

---

## Deliverable

A working local app, `npm install && npm start` from a fresh clone, listening on port 4000, with all 3 bugs present and the 2 seed users/orders in place. Confirm each of the 3 bugs works by testing it yourself before handing it back.

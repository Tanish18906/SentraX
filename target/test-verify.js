/**
 * Test script to verify VulnMart target application against the spec
 */

async function testVulnMart() {
  const assert = (name, cond, details) => {
    if (cond) {
      console.log(" \x1b[32m[PASS]\x1b[0m", name);
    } else {
      console.error(" \x1b[31m[FAIL]\x1b[0m", name, details || "");
      process.exitCode = 1;
    }
  };

  console.log("=== Testing VulnMart Target (http://localhost:4000) ===\n");

  // 1. Home page & static assets
  const homeRes = await fetch("http://localhost:4000/");
  assert("GET / (Home page returns 200)", homeRes.status === 200);

  const loginPageRes = await fetch("http://localhost:4000/login");
  assert("GET /login (Login page returns 200)", loginPageRes.status === 200);

  const reviewsPageRes = await fetch("http://localhost:4000/reviews");
  assert("GET /reviews (Reviews page returns 200)", reviewsPageRes.status === 200);

  const orderPageRes = await fetch("http://localhost:4000/order/1");
  assert("GET /order/1 (Order page returns 200)", orderPageRes.status === 200);

  // 2. SQL Injection: Login bypass
  const sqliRes = await fetch("http://localhost:4000/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "' OR 1=1--", password: "arbitrary_password" })
  });
  const sqliData = await sqliRes.json();
  assert(
    "POST /api/login SQLi bypass (HTTP 200 + token/success)",
    sqliRes.status === 200 && (sqliData.success === true || !!sqliData.token)
  );

  // SQL Injection: Negative test (invalid credentials without SQLi)
  const invalidLoginRes = await fetch("http://localhost:4000/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "invalid@vulnmart.test", password: "wrong" })
  });
  assert("POST /api/login invalid credentials returns HTTP 401", invalidLoginRes.status === 401);

  // 3. Stored XSS: Product reviews
  const xssMarker = "<script>alert('sentrax-test-xss')</script>";
  const postReviewRes = await fetch("http://localhost:4000/api/reviews", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ author: "tester", rating: 5, comment: xssMarker })
  });
  const postReviewData = await postReviewRes.json();
  assert("POST /api/reviews saves review (HTTP 201)", postReviewRes.status === 201 && postReviewData.success);

  const getReviewsHtmlRes = await fetch("http://localhost:4000/reviews");
  const reviewsHtml = await getReviewsHtmlRes.text();
  assert("GET /reviews reflects <script> payload unescaped", reviewsHtml.includes(xssMarker));

  // 4. IDOR: Order access
  const aliceLoginRes = await fetch("http://localhost:4000/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "alice@vulnmart.test", password: "alice123" })
  });
  const aliceLoginData = await aliceLoginRes.json();
  assert("Login as Alice succeeds", aliceLoginRes.status === 200 && aliceLoginData.user.email === "alice@vulnmart.test");

  const bobsOrderRes = await fetch("http://localhost:4000/api/order/2", {
    headers: { Authorization: `Bearer ${aliceLoginData.token}` }
  });
  const bobsOrderData = await bobsOrderRes.json();
  assert(
    "GET /api/order/2 returns Bob's order to Alice (IDOR confirmed)",
    bobsOrderRes.status === 200 &&
      bobsOrderData.buyer_email === "bob@vulnmart.test" &&
      bobsOrderData.product_name === "Desk Lamp" &&
      bobsOrderData.price === 34.99
  );

  const nonExistentOrderRes = await fetch("http://localhost:4000/api/order/999");
  assert("GET /api/order/999 returns HTTP 404", nonExistentOrderRes.status === 404);

  // 5. Broken Authentication: No rate limiting
  let failedCount = 0;
  for (let i = 0; i < 15; i++) {
    const r = await fetch("http://localhost:4000/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "alice@vulnmart.test", password: "wrong-pass-" + i })
    });
    if (r.status === 401) failedCount++;
  }
  assert("15 rapid failed logins all return HTTP 401 with no delay/lockout", failedCount === 15);

  console.log("\n=== All Tests Passed Successfully ===");
}

testVulnMart().catch(err => {
  console.error("Test error:", err);
  process.exit(1);
});

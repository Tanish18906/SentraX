/**
 * VulnMart — Deliberately Vulnerable Practice Target for SentraX AI
 * Stack: Node.js, Express, SQLite (node:sqlite)
 * Port: 4000
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('node:path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// 1. HOME & NAVIGATION
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>VulnMart — Fake Practice Store</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <header>
        <div class="nav-container">
          <a href="/" class="brand">🛒 VulnMart</a>
          <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/reviews">Reviews</a>
            <a href="/order/1">Order #1</a>
            <a href="/order/2">Order #2</a>
          </nav>
        </div>
      </header>

      <main class="container">
        <div class="hero">
          <h1>Welcome to VulnMart</h1>
          <p>A deliberately vulnerable online practice store built as a target for SentraX AI.</p>
        </div>

        <div class="product-grid">
          <div class="card">
            <h3>Wireless Mouse</h3>
            <p class="price">$19.99</p>
            <p>Ergonomic 2.4GHz wireless mouse with optical tracking.</p>
            <div class="card-actions">
              <a href="/order/1" class="btn">View Order #1 (Alice)</a>
              <a href="/reviews" class="btn btn-secondary">See Reviews</a>
            </div>
          </div>

          <div class="card">
            <h3>Desk Lamp</h3>
            <p class="price">$34.99</p>
            <p>Modern LED desk lamp with adjustable brightness settings.</p>
            <div class="card-actions">
              <a href="/order/2" class="btn">View Order #2 (Bob)</a>
              <a href="/reviews" class="btn btn-secondary">See Reviews</a>
            </div>
          </div>
        </div>

        <div class="api-links-section">
          <h3>Target API Endpoints</h3>
          <ul>
            <li><code>POST /api/login</code> — User authentication</li>
            <li><code>POST /api/reviews</code> — Submit product review</li>
            <li><code>GET /api/reviews</code> — List product reviews</li>
            <li><code>GET /api/order/:id</code> — Fetch order details by ID</li>
          </ul>
        </div>
      </main>

      <footer>
        <p>VulnMart Local Target — Running on port ${PORT}</p>
      </footer>
    </body>
    </html>
  `);
});

// ---------------------------------------------------------------------------
// 2. LOGIN PAGE & API (SQL Injection & Broken Authentication)
// ---------------------------------------------------------------------------
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>VulnMart — Login</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <header>
        <div class="nav-container">
          <a href="/" class="brand">🛒 VulnMart</a>
          <nav>
            <a href="/">Home</a>
            <a href="/login" class="active">Login</a>
            <a href="/reviews">Reviews</a>
            <a href="/order/1">Order #1</a>
          </nav>
        </div>
      </header>

      <main class="container">
        <div class="auth-card">
          <h2>Account Login</h2>
          <p class="subtitle">Sign in to access your orders and account.</p>

          <div id="alertBox" class="alert hidden"></div>

          <form id="loginForm" action="/api/login" method="POST">
            <div class="form-group">
              <label for="email">Email Address</label>
              <input type="text" id="email" name="email" placeholder="alice@vulnmart.test" required>
            </div>

            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" placeholder="••••••••" required>
            </div>

            <button type="submit" class="btn btn-primary btn-block">Sign In</button>
          </form>

          <div class="seed-info">
            <small><strong>Seed Accounts:</strong><br>
            • alice@vulnmart.test / alice123<br>
            • bob@vulnmart.test / bob123</small>
          </div>
        </div>
      </main>

      <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const email = document.getElementById('email').value;
          const password = document.getElementById('password').value;
          const alertBox = document.getElementById('alertBox');

          try {
            const res = await fetch('/api/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email, password })
            });
            const data = await res.json();

            if (res.ok && (data.success || data.token)) {
              alertBox.className = 'alert alert-success';
              alertBox.innerText = 'Login successful! Token: ' + (data.token || 'granted');
              alertBox.classList.remove('hidden');
              setTimeout(() => { window.location.href = '/'; }, 1000);
            } else {
              alertBox.className = 'alert alert-error';
              alertBox.innerText = data.error || 'Login failed';
              alertBox.classList.remove('hidden');
            }
          } catch (err) {
            alertBox.className = 'alert alert-error';
            alertBox.innerText = 'Request error: ' + err.message;
            alertBox.classList.remove('hidden');
          }
        });
      </script>
    </body>
    </html>
  `);
});

/**
 * POST /api/login
 * DELIBERATE BUG 1: SQL Injection (raw string concatenation without parameterization)
 * DELIBERATE BUG 2: Broken Authentication (no rate limiting, lockouts, or delay on failed attempts)
 */
app.post('/api/login', (req, res) => {
  const email = (req.body && req.body.email) !== undefined ? req.body.email : '';
  const password = (req.body && req.body.password) !== undefined ? req.body.password : '';

  // Vulnerable raw SQL string concatenation
  const query = `SELECT * FROM users WHERE email='${email}' AND password='${password}'`;

  try {
    const user = db.prepare(query).get();

    if (user) {
      const token = `token-vulnmart-${user.id}-${Date.now()}`;
      res.cookie('auth_token', token, { httpOnly: false });
      res.cookie('user_email', user.email, { httpOnly: false });
      return res.status(200).json({
        success: true,
        token: token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name || user.email
        },
        message: 'Login successful'
      });
    } else {
      // Immediate 401 with no rate limiting
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials'
      });
    }
  } catch (err) {
    // If the SQL syntax is broken by an unbalanced payload or error
    return res.status(500).json({
      success: false,
      error: 'Database error: ' + err.message,
      query: query
    });
  }
});

// ---------------------------------------------------------------------------
// 3. PRODUCT REVIEWS PAGE & API (Stored XSS)
// ---------------------------------------------------------------------------
/**
 * GET /reviews
 * DELIBERATE BUG: Stored XSS (rendering review comments directly into HTML without escaping)
 */
app.get('/reviews', (req, res) => {
  const reviews = db.prepare('SELECT * FROM reviews ORDER BY id DESC').all();

  // Unescaped rendering of review text directly into the page markup
  const reviewsHtml = reviews.map(r => `
    <div class="review-item">
      <div class="review-meta">
        <span class="review-author"><strong>${r.author || 'Anonymous'}</strong></span>
        <span class="review-rating">★ ${r.rating || 5}/5</span>
        <span class="review-date">${r.created_at || ''}</span>
      </div>
      <div class="review-comment">${r.comment}</div>
    </div>
  `).join('\n');

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>VulnMart — Product Reviews</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <header>
        <div class="nav-container">
          <a href="/" class="brand">🛒 VulnMart</a>
          <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/reviews" class="active">Reviews</a>
            <a href="/order/1">Order #1</a>
          </nav>
        </div>
      </header>

      <main class="container">
        <div class="page-header">
          <h2>Product Reviews: Wireless Mouse</h2>
          <p>Customer feedback and ratings for our top products.</p>
        </div>

        <div class="reviews-layout">
          <section class="review-form-card">
            <h3>Submit a Review</h3>
            <form id="reviewForm" action="/api/reviews" method="POST">
              <div class="form-group">
                <label for="author">Your Name / Email</label>
                <input type="text" id="author" name="author" placeholder="alice@vulnmart.test" value="alice@vulnmart.test">
              </div>

              <div class="form-group">
                <label for="rating">Rating (1-5)</label>
                <select id="rating" name="rating">
                  <option value="5">5 - Excellent</option>
                  <option value="4">4 - Very Good</option>
                  <option value="3">3 - Average</option>
                  <option value="2">2 - Poor</option>
                  <option value="1">1 - Terrible</option>
                </select>
              </div>

              <div class="form-group">
                <label for="comment">Review Text</label>
                <textarea id="comment" name="comment" rows="4" placeholder="Write your review here..." required></textarea>
              </div>

              <button type="submit" class="btn btn-primary">Post Review</button>
            </form>
          </section>

          <section class="reviews-list-section">
            <h3>Recent Reviews (${reviews.length})</h3>
            <div id="reviewsContainer" class="reviews-container">
              ${reviewsHtml}
            </div>
          </section>
        </div>
      </main>

      <script>
        document.getElementById('reviewForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const author = document.getElementById('author').value;
          const rating = parseInt(document.getElementById('rating').value, 10);
          const comment = document.getElementById('comment').value;

          const res = await fetch('/api/reviews', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ author, rating, comment })
          });

          if (res.ok) {
            window.location.reload();
          } else {
            alert('Failed to post review');
          }
        });
      </script>
    </body>
    </html>
  `);
});

/**
 * POST /api/reviews
 * Saves review to SQLite database
 */
app.post('/api/reviews', (req, res) => {
  const comment = req.body && (req.body.comment !== undefined ? req.body.comment : req.body.review);
  const rating = req.body && req.body.rating ? parseInt(req.body.rating, 10) : 5;
  const author = (req.body && req.body.author) || 'Anonymous';

  if (!comment) {
    return res.status(400).json({ error: 'Review comment is required' });
  }

  const stmt = db.prepare('INSERT INTO reviews (rating, comment, author) VALUES (?, ?, ?)');
  const info = stmt.run(rating, comment, author);

  return res.status(201).json({
    success: true,
    review: {
      id: info.lastInsertRowid,
      rating: rating,
      comment: comment,
      author: author
    }
  });
});

/**
 * GET /api/reviews
 * Returns JSON list of all reviews
 */
app.get('/api/reviews', (req, res) => {
  const reviews = db.prepare('SELECT * FROM reviews ORDER BY id DESC').all();
  return res.status(200).json(reviews);
});

// ---------------------------------------------------------------------------
// 4. ORDER DETAILS PAGE & API (IDOR)
// ---------------------------------------------------------------------------
/**
 * GET /order/:id
 * Displays the order details page
 */
app.get('/order/:id', (req, res) => {
  const orderId = req.params.id;
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>VulnMart — Order #${orderId}</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <header>
        <div class="nav-container">
          <a href="/" class="brand">🛒 VulnMart</a>
          <nav>
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/reviews">Reviews</a>
            <a href="/order/1">Order #1</a>
            <a href="/order/2">Order #2</a>
          </nav>
        </div>
      </header>

      <main class="container">
        <div class="order-card">
          <h2>Order Details: #${orderId}</h2>

          ${order ? `
            <div class="order-details">
              <div class="order-row">
                <span class="label">Order ID:</span>
                <span class="value">#${order.id}</span>
              </div>
              <div class="order-row">
                <span class="label">Product Name:</span>
                <span class="value">${order.product_name}</span>
              </div>
              <div class="order-row">
                <span class="label">Total Price:</span>
                <span class="value price">$${order.price.toFixed(2)}</span>
              </div>
              <div class="order-row">
                <span class="label">Buyer Email:</span>
                <span class="value">${order.buyer_email}</span>
              </div>
            </div>
          ` : `
            <div class="alert alert-error">
              Order #${orderId} not found.
            </div>
          `}

          <div class="order-nav">
            <p>Try switching order ID in the URL to demonstrate IDOR:</p>
            <a href="/order/1" class="btn btn-secondary">View Order #1 (Alice)</a>
            <a href="/order/2" class="btn btn-secondary">View Order #2 (Bob)</a>
          </div>
        </div>
      </main>
    </body>
    </html>
  `);
});

/**
 * GET /api/order/:id
 * DELIBERATE BUG: Insecure Direct Object Reference (IDOR)
 * Returns whatever order ID is requested in the URL without checking ownership or req.user.
 */
app.get('/api/order/:id', (req, res) => {
  const orderId = req.params.id;
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);

  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }

  // Returns order object with buyer email and owner fields
  return res.status(200).json({
    id: order.id,
    user_id: order.user_id,
    product_name: order.product_name,
    price: order.price,
    buyer_email: order.buyer_email,
    email: order.buyer_email,
    owner: order.buyer_email
  });
});

// ---------------------------------------------------------------------------
// 5. SERVER START
// ---------------------------------------------------------------------------
const server = app.listen(PORT, () => {
  console.log(`[VulnMart] Server running on http://localhost:${PORT}`);
  console.log(`[VulnMart] SQLi Login: POST /api/login`);
  console.log(`[VulnMart] Stored XSS: POST /api/reviews -> GET /reviews`);
  console.log(`[VulnMart] IDOR Orders: GET /api/order/:id`);
});

module.exports = { app, server };

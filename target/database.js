/**
 * VulnMart SQLite Database Initialization & Seeding
 * Uses Node.js built-in `node:sqlite` (DatabaseSync)
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

const DB_PATH = path.join(__dirname, 'vulnmart.db');
const db = new DatabaseSync(DB_PATH);

// Initialize tables
function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      price REAL NOT NULL,
      buyer_email TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rating INTEGER DEFAULT 5,
      comment TEXT NOT NULL,
      author TEXT DEFAULT 'Anonymous',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed Users if not present
  const usersCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (usersCount === 0) {
    db.exec(`
      INSERT INTO users (id, email, password, name) VALUES
        (1, 'alice@vulnmart.test', 'alice123', 'Alice Smith'),
        (2, 'bob@vulnmart.test', 'bob123', 'Bob Jones');
    `);
    console.log('[VulnMart DB] Seeded users: Alice and Bob');
  }

  // Seed Orders if not present
  const ordersCount = db.prepare('SELECT COUNT(*) as count FROM orders').get().count;
  if (ordersCount === 0) {
    db.exec(`
      INSERT INTO orders (id, user_id, product_name, price, buyer_email) VALUES
        (1, 1, 'Wireless Mouse', 19.99, 'alice@vulnmart.test'),
        (2, 2, 'Desk Lamp', 34.99, 'bob@vulnmart.test');
    `);
    console.log('[VulnMart DB] Seeded orders: Order #1 (Alice), Order #2 (Bob)');
  }

  // Seed Reviews if not present
  const reviewsCount = db.prepare('SELECT COUNT(*) as count FROM reviews').get().count;
  if (reviewsCount === 0) {
    db.exec(`
      INSERT INTO reviews (id, rating, comment, author) VALUES
        (1, 5, 'Great ergonomic wireless mouse! Battery life is unbelievable.', 'alice@vulnmart.test'),
        (2, 4, 'Very sturdy desk lamp with adjustable brightness settings.', 'bob@vulnmart.test');
    `);
    console.log('[VulnMart DB] Seeded sample product reviews');
  }
}

initDb();

module.exports = db;

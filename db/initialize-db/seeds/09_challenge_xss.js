const sqlite3 = require('sqlite3').verbose();

const vulnerableComments = [
  ['John Doe', 'Great product! Highly recommended.', 1],
  ['Jane Smith', 'Good value for money.', 1],
  ['Hacker', '<script>alert("XSS Test")</script>This is vulnerable!', 2],
  ['Customer', 'Fast delivery and good packaging.', 2],
  ['Tester', '<img src=x onerror=alert("XSS")>Product review', 3],
  ['User123', 'Normal comment about the product quality.', 3],
];
const vulnerablePosts = [
  ['Welcome to Our Store', 'Welcome message with <b>HTML</b> content', 'Admin'],
  ['New Products', 'Check out our <script>alert("XSS")</script> new products!', 'Manager'],
  ['Sale Event', '<h1>Big Sale!</h1> Up to 50% off selected items.', 'Marketing'],
  ['Customer Reviews', 'Read what our <em>customers</em> are saying...', 'Support'],
];
const vulnerableProfiles = [
  ['Admin User', 'Store administrator', 'https://admin.store.local', '{"twitter": "@admin"}'],
  ['Manager', 'Store manager <script>alert("XSS")</script>', 'javascript:alert("XSS")', '{"linkedin": "manager"}'],
  ['Customer', 'Happy customer!', 'https://customer.example.com', '{"facebook": "customer123"}'],
];

// Note: xss_workshop_emails global seed rows are no longer seeded.
// The Email Summarization XSS exercise (xss_e1/e2/e3) now uses the real SharkLaser/GuerrillaMail
// API via sharkLasersScraper.js — inbox data comes from the user's configured temp email address.

function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    vulnerableComments.forEach(c => db.run(`INSERT OR IGNORE INTO vulnerable_comments (user_name, comment_content, product_id) VALUES (?,?,?)`, c));
    vulnerablePosts.forEach(p => db.run(`INSERT OR IGNORE INTO vulnerable_posts (title, content, author) VALUES (?,?,?)`, p));
    vulnerableProfiles.forEach(p => db.run(`INSERT OR IGNORE INTO vulnerable_profiles (display_name, bio, website, social_links) VALUES (?,?,?,?)`, p));
    db.close(resolve);
  });
}

module.exports = { runSeed };

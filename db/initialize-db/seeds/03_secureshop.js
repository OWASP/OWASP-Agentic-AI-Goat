const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const categories = ['Electronics', 'Clothing', 'Books', 'Home & Garden', 'Sports & Outdoors', 'Health & Beauty', 'Toys & Games', 'Automotive'];
const defaultUsers = [
  { username: 'customer1', email: 'customer1@secureshop.com', password: bcrypt.hashSync('password123', 10), role: 'customer', full_name: 'John Customer', phone: '555-0101', address: '123 Customer St' },
  { username: 'merchant1', email: 'merchant1@secureshop.com', password: bcrypt.hashSync('password123', 10), role: 'retailer', full_name: 'Jane Merchant', phone: '555-0201', address: '456 Business Ave' },
  { username: 'admin', email: 'admin@secureshop.com', password: bcrypt.hashSync('admin123', 10), role: 'retailer', full_name: 'Admin User', phone: '555-0301', address: '789 Admin Blvd' },
];
const sampleProducts = [
  ['Wireless Bluetooth Headphones', 'High-quality wireless headphones with noise cancellation', 99.99, 'Electronics', 50, 2, '/images/headphones.jpg'],
  ['Smart Fitness Watch', 'Track your fitness goals with this advanced smartwatch', 199.99, 'Electronics', 30, 2, '/images/smartwatch.jpg'],
  ['Organic Cotton T-Shirt', 'Comfortable and eco-friendly cotton t-shirt', 24.99, 'Clothing', 100, 2, '/images/tshirt.jpg'],
  ['Programming Book Set', 'Complete guide to modern web development', 79.99, 'Books', 25, 2, '/images/books.jpg'],
  ['Yoga Mat Premium', 'Non-slip premium yoga mat', 39.99, 'Sports & Outdoors', 75, 2, '/images/yogamat.jpg'],
];

function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath);
    categories.forEach(name => db.run(`INSERT OR IGNORE INTO categories (name) VALUES (?)`, [name]));
    defaultUsers.forEach(u => {
      db.run(`INSERT OR IGNORE INTO shop_users (username, email, password, role, full_name, phone, address) VALUES (?,?,?,?,?,?,?)`,
        [u.username, u.email, u.password, u.role, u.full_name, u.phone, u.address]);
    });
    sampleProducts.forEach(p => {
      db.run(`INSERT OR IGNORE INTO products (name, description, price, category, stock_quantity, retailer_id, image_url) VALUES (?,?,?,?,?,?,?)`, p);
    });
    db.close(resolve);
  });
}

module.exports = { runSeed };

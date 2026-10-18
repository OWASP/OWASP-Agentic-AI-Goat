'use strict';
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const PRODUCTS = [
  { product_id: 'PROD-001', name: 'Wireless Noise-Cancelling Headphones', category: 'Electronics', price: 149.99, description: 'Premium over-ear headphones with active noise cancellation and 30-hour battery life.', stock: 45 },
  { product_id: 'PROD-002', name: 'Mechanical Keyboard', category: 'Electronics', price: 89.99, description: 'Compact TKL mechanical keyboard with Cherry MX switches and RGB backlighting.', stock: 62 },
  { product_id: 'PROD-003', name: 'USB-C Hub 7-in-1', category: 'Electronics', price: 34.99, description: 'Multiport adapter with HDMI, USB-A, SD card reader and 100W PD charging.', stock: 130 },
  { product_id: 'PROD-004', name: 'Webcam 1080p HD', category: 'Electronics', price: 59.99, description: 'Full HD webcam with built-in microphone and auto light correction.', stock: 88 },
  { product_id: 'PROD-005', name: 'Standing Desk Converter', category: 'Home', price: 129.99, description: 'Height-adjustable desk riser for sit-stand work setup, fits up to 30" monitor.', stock: 27 },
  { product_id: 'PROD-006', name: 'Ergonomic Office Chair', category: 'Home', price: 299.99, description: 'Lumbar-support office chair with adjustable armrests and breathable mesh back.', stock: 15 },
  { product_id: 'PROD-007', name: 'LED Desk Lamp', category: 'Home', price: 39.99, description: 'Dimmable desk lamp with 5 color temperature modes and USB charging port.', stock: 200 },
  { product_id: 'PROD-008', name: 'Python Programming (Book)', category: 'Books', price: 39.99, description: 'Comprehensive guide to Python from beginner to expert, 3rd edition.', stock: 75 },
  { product_id: 'PROD-009', name: 'Clean Code (Book)', category: 'Books', price: 34.99, description: 'A handbook of agile software craftsmanship by Robert C. Martin.', stock: 50 },
  { product_id: 'PROD-010', name: 'The Pragmatic Programmer (Book)', category: 'Books', price: 44.99, description: 'Your journey to mastery — 20th anniversary edition.', stock: 40 },
  { product_id: 'PROD-011', name: 'Laptop Sleeve 15"', category: 'Accessories', price: 24.99, description: 'Water-resistant neoprene sleeve with accessory pocket for 15" laptops.', stock: 180 },
  { product_id: 'PROD-012', name: 'Wireless Mouse', category: 'Electronics', price: 29.99, description: 'Ergonomic wireless mouse with silent clicks and 12-month battery life.', stock: 95 },
  { product_id: 'PROD-013', name: 'Monitor Privacy Screen 27"', category: 'Accessories', price: 49.99, description: 'Anti-glare privacy filter for 27" widescreen monitors.', stock: 33 },
  { product_id: 'PROD-014', name: 'Cable Management Kit', category: 'Accessories', price: 14.99, description: 'Set of 30 reusable velcro cable ties + 10 adhesive cable clips.', stock: 250 },
  { product_id: 'PROD-015', name: 'Smart Power Strip', category: 'Electronics', price: 44.99, description: '6-outlet surge protector with 4 USB ports and individual switch control.', stock: 60 },
  // Expanded catalog
  { product_id: 'PROD-016', name: '4K Monitor 27"', category: 'Electronics', price: 349.99, description: '27-inch 4K UHD IPS display with USB-C connectivity and 99% sRGB color accuracy.', stock: 22 },
  { product_id: 'PROD-017', name: 'Noise-Cancelling Earbuds', category: 'Electronics', price: 79.99, description: 'True wireless earbuds with active noise cancellation, 8-hour battery, IPX4 water resistance.', stock: 110 },
  { product_id: 'PROD-018', name: 'Portable SSD 1TB', category: 'Electronics', price: 89.99, description: 'USB-C portable solid-state drive with 1050 MB/s read speed, shock-resistant.', stock: 55 },
  { product_id: 'PROD-019', name: 'Laptop Stand Adjustable', category: 'Accessories', price: 39.99, description: 'Aluminum laptop riser with 6 height levels, foldable and compatible with 10"–17" laptops.', stock: 140 },
  { product_id: 'PROD-020', name: 'Blue Light Glasses', category: 'Accessories', price: 19.99, description: 'Non-prescription blue-light-blocking lenses to reduce eye strain during screen time.', stock: 300 },
  { product_id: 'PROD-021', name: 'Whiteboard 36"x24"', category: 'Office', price: 54.99, description: 'Magnetic dry-erase board with aluminum frame, includes marker tray and 3 markers.', stock: 38 },
  { product_id: 'PROD-022', name: 'Desk Mat XL', category: 'Accessories', price: 29.99, description: 'Extra-large 90×40 cm desk pad with non-slip base, waterproof surface, and stitched edges.', stock: 175 },
  { product_id: 'PROD-023', name: 'Mechanical Pencil Set', category: 'Stationery', price: 12.99, description: 'Pack of 6 mechanical pencils (0.5 mm & 0.7 mm) with 30 refill leads and eraser caps.', stock: 400 },
  { product_id: 'PROD-024', name: 'Wireless Charging Pad', category: 'Electronics', price: 24.99, description: '15W fast wireless charger compatible with Qi devices, LED indicator, anti-slip surface.', stock: 120 },
  { product_id: 'PROD-025', name: 'Coffee Mug Warmer', category: 'Kitchen', price: 22.99, description: 'Electric desk mug warmer with auto shut-off after 4 hours, keeps beverages at 55°C.', stock: 85 },
];

const ORDERS = [
  // current_user — 10 orders covering all statuses
  { order_number: 'ORD-2024-001', user_id: 'current_user', product_name: 'Wireless Noise-Cancelling Headphones', quantity: 1, unit_price: 149.99, total_amount: 149.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'delivered',   payment_method: 'credit_card', created_at: '2024-01-15 10:32:00' },
  { order_number: 'ORD-2024-007', user_id: 'current_user', product_name: 'Mechanical Keyboard',                  quantity: 1, unit_price:  89.99, total_amount:  89.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'shipped',    payment_method: 'paypal',      created_at: '2024-02-20 14:18:00' },
  { order_number: 'ORD-2024-011', user_id: 'current_user', product_name: 'LED Desk Lamp',                        quantity: 2, unit_price:  39.99, total_amount:  79.98, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'processing', payment_method: 'credit_card', created_at: '2024-03-05 09:05:00' },
  { order_number: 'ORD-2024-021', user_id: 'current_user', product_name: 'USB-C Hub 7-in-1',                     quantity: 1, unit_price:  34.99, total_amount:  34.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'delivered',   payment_method: 'paypal',      created_at: '2024-01-28 11:20:00' },
  { order_number: 'ORD-2024-022', user_id: 'current_user', product_name: 'Laptop Stand Adjustable',              quantity: 1, unit_price:  39.99, total_amount:  39.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'delivered',   payment_method: 'credit_card', created_at: '2024-02-08 08:45:00' },
  { order_number: 'ORD-2024-023', user_id: 'current_user', product_name: 'Wireless Mouse',                       quantity: 1, unit_price:  29.99, total_amount:  29.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'shipped',    payment_method: 'debit_card',  created_at: '2024-03-01 16:10:00' },
  { order_number: 'ORD-2024-024', user_id: 'current_user', product_name: 'Python Programming (Book)',             quantity: 1, unit_price:  39.99, total_amount:  39.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'delivered',   payment_method: 'credit_card', created_at: '2024-01-10 13:55:00' },
  { order_number: 'ORD-2024-025', user_id: 'current_user', product_name: 'Portable SSD 1TB',                     quantity: 1, unit_price:  89.99, total_amount:  89.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'delivered',   payment_method: 'apple_pay',   created_at: '2024-02-15 09:30:00' },
  { order_number: 'ORD-2024-026', user_id: 'current_user', product_name: 'Noise-Cancelling Earbuds',             quantity: 1, unit_price:  79.99, total_amount:  79.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'cancelled',  payment_method: 'paypal',      created_at: '2024-02-25 14:00:00' },
  { order_number: 'ORD-2024-027', user_id: 'current_user', product_name: '4K Monitor 27"',                       quantity: 1, unit_price: 349.99, total_amount: 349.99, shipping_address: '123 Main St, San Francisco, CA 94102', status: 'processing', payment_method: 'credit_card', created_at: '2024-03-10 11:22:00' },
  // Other users
  { order_number: 'ORD-2024-002', user_id: 'user_alice',   product_name: 'Ergonomic Office Chair',               quantity: 1, unit_price: 299.99, total_amount: 299.99, shipping_address: '456 Oak Ave, Austin, TX 78701',          status: 'delivered',   payment_method: 'credit_card', created_at: '2024-01-18 09:45:00' },
  { order_number: 'ORD-2024-003', user_id: 'user_bob',     product_name: 'USB-C Hub 7-in-1',                     quantity: 2, unit_price:  34.99, total_amount:  69.98, shipping_address: '789 Pine Rd, Seattle, WA 98101',         status: 'delivered',   payment_method: 'paypal',      created_at: '2024-01-20 16:22:00' },
  { order_number: 'ORD-2024-004', user_id: 'user_carol',   product_name: 'Python Programming (Book)',             quantity: 1, unit_price:  39.99, total_amount:  39.99, shipping_address: '321 Elm St, Boston, MA 02101',           status: 'delivered',   payment_method: 'debit_card',  created_at: '2024-01-25 11:10:00' },
  { order_number: 'ORD-2024-005', user_id: 'user_dave',    product_name: 'Standing Desk Converter',              quantity: 1, unit_price: 129.99, total_amount: 129.99, shipping_address: '654 Maple Dr, Chicago, IL 60601',        status: 'shipped',    payment_method: 'credit_card', created_at: '2024-02-01 08:33:00' },
  { order_number: 'ORD-2024-006', user_id: 'user_eve',     product_name: 'Webcam 1080p HD',                      quantity: 1, unit_price:  59.99, total_amount:  59.99, shipping_address: '987 Cedar Ln, Denver, CO 80201',         status: 'processing', payment_method: 'apple_pay',   created_at: '2024-02-05 17:55:00' },
  { order_number: 'ORD-2024-008', user_id: 'user_frank',   product_name: 'Wireless Mouse',                       quantity: 3, unit_price:  29.99, total_amount:  89.97, shipping_address: '147 Birch Way, Miami, FL 33101',         status: 'delivered',   payment_method: 'credit_card', created_at: '2024-02-08 12:40:00' },
  { order_number: 'ORD-2024-009', user_id: 'user_grace',   product_name: 'Monitor Privacy Screen 27"',           quantity: 1, unit_price:  49.99, total_amount:  49.99, shipping_address: '258 Spruce Ave, Portland, OR 97201',     status: 'pending',    payment_method: 'paypal',      created_at: '2024-02-10 15:28:00' },
  { order_number: 'ORD-2024-010', user_id: 'user_henry',   product_name: 'Smart Power Strip',                    quantity: 2, unit_price:  44.99, total_amount:  89.98, shipping_address: '369 Willow Ct, Nashville, TN 37201',     status: 'shipped',    payment_method: 'credit_card', created_at: '2024-02-15 10:12:00' },
];

const RECEIPTS = [
  { order_number: 'ORD-2024-001', receipt_number: 'RCP-2024-001', amount: 149.99, payment_method: 'credit_card', issued_at: '2024-01-15 10:33:00' },
  { order_number: 'ORD-2024-021', receipt_number: 'RCP-2024-021', amount:  34.99, payment_method: 'paypal',      issued_at: '2024-01-28 11:21:00' },
  { order_number: 'ORD-2024-022', receipt_number: 'RCP-2024-022', amount:  39.99, payment_method: 'credit_card', issued_at: '2024-02-08 08:46:00' },
  { order_number: 'ORD-2024-024', receipt_number: 'RCP-2024-024', amount:  39.99, payment_method: 'credit_card', issued_at: '2024-01-10 13:56:00' },
  { order_number: 'ORD-2024-025', receipt_number: 'RCP-2024-025', amount:  89.99, payment_method: 'apple_pay',   issued_at: '2024-02-15 09:31:00' },
  { order_number: 'ORD-2024-002', receipt_number: 'RCP-2024-002', amount: 299.99, payment_method: 'credit_card', issued_at: '2024-01-18 09:46:00' },
  { order_number: 'ORD-2024-003', receipt_number: 'RCP-2024-003', amount:  69.98, payment_method: 'paypal',      issued_at: '2024-01-20 16:23:00' },
  { order_number: 'ORD-2024-004', receipt_number: 'RCP-2024-004', amount:  39.99, payment_method: 'debit_card',  issued_at: '2024-01-25 11:11:00' },
  { order_number: 'ORD-2024-008', receipt_number: 'RCP-2024-008', amount:  89.97, payment_method: 'credit_card', issued_at: '2024-02-08 12:41:00' },
];

// Pre-filled cart for current_user — shows up immediately on "view cart"
const CART = [
  { user_id: 'current_user', product_name: 'Wireless Charging Pad', quantity: 1, unit_price: 24.99 },
  { user_id: 'current_user', product_name: 'Desk Mat XL',           quantity: 1, unit_price: 29.99 },
];

async function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
    });
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');

      const insertProduct = db.prepare(
        'INSERT OR IGNORE INTO products (product_id, name, category, price, description, stock, available) VALUES (?, ?, ?, ?, ?, ?, 1)'
      );
      for (const p of PRODUCTS) {
        insertProduct.run(p.product_id, p.name, p.category, p.price, p.description, p.stock);
      }
      insertProduct.finalize();

      const insertOrder = db.prepare(
        'INSERT OR IGNORE INTO orders (order_number, user_id, product_name, quantity, unit_price, total_amount, shipping_address, status, payment_method, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      );
      for (const o of ORDERS) {
        insertOrder.run(o.order_number, o.user_id, o.product_name, o.quantity, o.unit_price, o.total_amount, o.shipping_address, o.status, o.payment_method, o.created_at);
      }
      insertOrder.finalize();

      const insertReceipt = db.prepare(
        'INSERT OR IGNORE INTO receipts (order_number, receipt_number, amount, payment_method, issued_at) VALUES (?, ?, ?, ?, ?)'
      );
      for (const r of RECEIPTS) {
        insertReceipt.run(r.order_number, r.receipt_number, r.amount, r.payment_method, r.issued_at);
      }
      insertReceipt.finalize();

      const insertCart = db.prepare(
        'INSERT OR IGNORE INTO cart (user_id, product_name, quantity, unit_price) VALUES (?, ?, ?, ?)'
      );
      for (const c of CART) {
        insertCart.run(c.user_id, c.product_name, c.quantity, c.unit_price);
      }
      insertCart.finalize();

      db.run('COMMIT', (err) => {
        db.close();
        if (err) reject(err);
        else resolve();
      });
    });
  });
}

module.exports = { runSeed };

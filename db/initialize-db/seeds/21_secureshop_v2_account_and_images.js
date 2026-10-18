/**
 * SecureShop v2 — M8 Wave 5B U2/U4 seed.
 *
 * Idempotent seed applied against secureshop.db. Populates:
 *   - product_images: 3 real picsum.photos entries per product so the Product
 *     page gallery has real thumbnails to render (no more "placeholder" pads).
 *   - user_addresses: 1 default address per seeded student/customer so the
 *     Account → Addresses tab has real rows on first login.
 *
 * Skips per-table if rows already exist.
 */

const Database = require('better-sqlite3');

module.exports = function seed(dbPath) {
  const db = new Database(dbPath);

  // --- Product images -------------------------------------------------------
  try {
    const existing = db.prepare('SELECT COUNT(*) AS c FROM product_images').get().c;
    if (existing < 30) {
      const products = db.prepare('SELECT id, image_url FROM products').all();
      const insertImg = db.prepare(
        'INSERT INTO product_images (product_id, path, mime) VALUES (?, ?, ?)'
      );
      const tx = db.transaction(() => {
        for (const p of products) {
          // Primary image = product's canonical image_url (fallback to picsum).
          const primary = p.image_url || `https://picsum.photos/seed/ss_p${p.id}/600/800`;
          insertImg.run(p.id, primary, 'image/jpeg');
          // Two alternate angles using deterministic seeds so refreshes stay stable.
          insertImg.run(p.id, `https://picsum.photos/seed/ss_${p.id}_a/600/800`, 'image/jpeg');
          insertImg.run(p.id, `https://picsum.photos/seed/ss_${p.id}_b/600/800`, 'image/jpeg');
        }
      });
      tx();
      const now = db.prepare('SELECT COUNT(*) AS c FROM product_images').get().c;
      console.log(`  \u2713 seed 21_secureshop_v2_account_and_images.js — product_images: ${now} rows`);
    } else {
      console.log('  \u2713 seed 21_secureshop_v2_account_and_images.js — product_images: skipped');
    }
  } catch (e) {
    console.log(`  ! seed 21 product_images skipped: ${e.message}`);
  }

  // --- User addresses -------------------------------------------------------
  try {
    const existing = db.prepare('SELECT COUNT(*) AS c FROM user_addresses').get().c;
    if (existing < 3) {
      const addrs = [
        ['student_c', 'Home',   '123 Main St',     null, 'Palo Alto',    'CA', '94301', '555-0100', 1],
        ['alice',     'Home',   '22 Oak Ave',      null, 'San Francisco','CA', '94110', '555-0201', 1],
        ['bob',       'Home',   '33 Oak Ave',      null, 'Berkeley',     'CA', '94704', '555-0202', 1],
        ['student_c', 'Work',   '500 Market St',   'Suite 400', 'San Francisco', 'CA', '94105', '555-0100', 0],
      ];
      const findUser = db.prepare('SELECT id FROM shop_users WHERE username = ?');
      const insertAddr = db.prepare(`
        INSERT INTO user_addresses (user_id, label, line1, line2, city, state, zip, phone, is_default)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const tx = db.transaction(() => {
        for (const [uname, label, l1, l2, city, state, zip, phone, def] of addrs) {
          const u = findUser.get(uname);
          if (u) insertAddr.run(u.id, label, l1, l2, city, state, zip, phone, def);
        }
      });
      tx();
      console.log('  \u2713 seed 21_secureshop_v2_account_and_images.js — user_addresses seeded');
    } else {
      console.log('  \u2713 seed 21_secureshop_v2_account_and_images.js — user_addresses: skipped');
    }
  } catch (e) {
    console.log(`  ! seed 21 user_addresses skipped: ${e.message}`);
  }

  db.close();
};

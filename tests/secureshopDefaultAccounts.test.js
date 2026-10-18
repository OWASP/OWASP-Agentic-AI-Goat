'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const snapshot = require('../db/postgres/seeds/secureshop.json');

const practiceRoles = Object.freeze({
  student_customer: 'customer',
  student_merchant: 'merchant',
  student_admin: 'admin',
});

test('fresh SecureShop seed carries the three advertised shop-only logins', async () => {
  const rows = snapshot.shop_users;
  assert.equal(new Set(rows.map(row => row.username)).size, rows.length);
  assert.equal(new Set(rows.map(row => row.email)).size, rows.length);
  for (const [username, role] of Object.entries(practiceRoles)) {
    const matches = rows.filter(row => row.username === username);
    assert.equal(matches.length, 1, username);
    assert.equal(matches[0].role, role);
    assert.equal(await bcrypt.compare('student123', matches[0].password), true, username);
  }
  for (const [username, role] of [['student_c', 'customer'], ['student_m', 'merchant'], ['student_a', 'admin']]) {
    assert.equal(rows.find(row => row.username === username)?.role, role);
  }
});

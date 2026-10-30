'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const USERNAMES = Object.freeze({
  PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL: 'dvaia_identity_runtime',
  PG_XSS_EMAIL_ROUTE_IDENTITY_MIGRATION_URL: 'dvaia_identity_migration',
  PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL: 'dvaia_xss_runtime',
  PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL: 'dvaia_xss_migration',
  PG_XSS_EMAIL_ROUTE_CTF_RUNTIME_URL: 'dvaia_ctf_runtime',
  PG_XSS_EMAIL_ROUTE_CTF_MIGRATION_URL: 'dvaia_ctf_migration',
});

function privateOwned(target, kind) {
  const link = fs.lstatSync(target);
  assert.equal(link.isSymbolicLink(), false, `${kind} must not be a symlink`);
  assert.equal(link.uid, process.getuid(), `${kind} must be owned by this user`);
  assert.equal(link.mode & 0o077, 0, `${kind} must be private`);
  return link;
}

function verifyCurrentCheckout({ keys, cohort }) {
  if (process.env.OWASP_AI_GOAT_XSS_CURRENT_CHECKOUT !== 'yes') return null;
  assert.ok(Array.isArray(keys) && keys.length >= 4);
  assert.match(cohort, /^(?:route|builder|email|reflected|stored_user|stored_llm)$/);

  const workspace = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  const sourceRoot = fs.realpathSync(path.resolve(__dirname, '../..'));
  assert.equal(workspace, sourceRoot, 'current-checkout launcher must run the canonical test source root');
  const workspaceStat = fs.statSync(workspace);

  const receiptPath = process.env.OWASP_AI_GOAT_XSS_CURRENT_CHECKOUT_RECEIPT;
  assert.ok(receiptPath && path.isAbsolute(receiptPath), 'absolute current-checkout receipt is required');
  const receiptLink = privateOwned(receiptPath, 'current-checkout receipt');
  assert.equal(receiptLink.isFile(), true, 'current-checkout receipt must be a file');
  assert.equal(receiptLink.mode & 0o777, 0o600, 'current-checkout receipt mode must be 0600');
  privateOwned(path.dirname(receiptPath), 'current-checkout receipt directory');
  const receiptBytes = fs.readFileSync(receiptPath);
  assert.equal(crypto.createHash('sha256').update(receiptBytes).digest('hex'),
    process.env.OWASP_AI_GOAT_XSS_CURRENT_CHECKOUT_RECEIPT_SHA256);
  const receipt = JSON.parse(receiptBytes);
  assert.deepEqual(Object.keys(receipt).sort(), [
    'cohort', 'databasePort', 'mailpitApiPort', 'mailpitSmtpPort', 'runNonce', 'runtimeRoot',
    'sourceDigest', 'version', 'workspace', 'workspaceDev', 'workspaceIno',
  ]);
  assert.equal(receipt.version, 1);
  assert.equal(receipt.cohort, cohort);
  assert.equal(receipt.workspace, workspace);
  assert.equal(String(receipt.workspaceDev), String(workspaceStat.dev));
  assert.equal(String(receipt.workspaceIno), String(workspaceStat.ino));
  assert.match(receipt.sourceDigest, /^[a-f0-9]{64}$/);
  assert.match(receipt.runNonce, /^[a-f0-9]{32}$/);

  const runtimeRoot = fs.realpathSync(process.env.OWASP_AI_GOAT_XSS_RENDERED_RUNTIME_ROOT);
  assert.equal(receipt.runtimeRoot, runtimeRoot);
  privateOwned(runtimeRoot, 'rendered runtime root');
  assert.notEqual(runtimeRoot, workspace);
  assert.ok(!runtimeRoot.startsWith(`${workspace}${path.sep}`));

  const parsed = new Map();
  for (const key of keys) {
    assert.ok(USERNAMES[key], `unsupported disposable URL key: ${key}`);
    const url = new URL(process.env[key]);
    assert.equal(url.protocol, 'postgresql:');
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.password, '');
    assert.equal(url.username, USERNAMES[key]);
    assert.equal(Number(url.port), receipt.databasePort);
    assert.notEqual(url.port, '5432');
    assert.match(url.pathname, /^\/owasp_ai_goat_test_xss_email_route_(?:identity|xss|ctf)$/);
    parsed.set(key, url);
  }
  assert.notEqual(parsed.get(keys[0]).pathname, parsed.get(keys[2]).pathname);
  assert.equal(process.env.MAILPIT_SMTP_HOST, '127.0.0.1');
  assert.equal(Number(process.env.MAILPIT_SMTP_PORT), receipt.mailpitSmtpPort);
  assert.notEqual(process.env.MAILPIT_SMTP_PORT, '1025');
  const mailpit = new URL(process.env.MAILPIT_API_URL);
  assert.equal(mailpit.protocol, 'http:');
  assert.equal(mailpit.hostname, '127.0.0.1');
  assert.equal(Number(mailpit.port), receipt.mailpitApiPort);
  assert.notEqual(mailpit.port, '8025');
  return workspace;
}

module.exports = { verifyCurrentCheckout };

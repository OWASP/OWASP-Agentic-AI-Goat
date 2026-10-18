'use strict';

// Explicit qualification inventory. No directory or name-pattern exclusion.
const fs = require('node:fs');
const path = require('node:path');
const launcher = 'tests/postgres/run-secureshop-agent-host-transport-main.py';
const command = `python3 -B ${launcher} --cohort vuln --browser <path> --browser-sha256 <sha> --browser-root <root>`;

function rows(files, kind, reason) {
  return Object.freeze(files.map(file => Object.freeze({ file, kind, reason, launcher, command })));
}
const schemaFirst = rows([
  "tests/secureshop/integration/db-schema.test.js"
], 'schemaFirst', "Canonical PostgreSQL migration/seed schema proof; runs first before vulnerability resets.");

const nativePg = rows([
  "tests/secureshop/integration/rbac-tool-permissions.test.js",
  "tests/secureshop/vuln/chains/audit-log-injection.test.js",
  "tests/secureshop/vuln/chains/mcp01-rug-pull.test.js",
  "tests/secureshop/vuln/chains/mcp05-external-tool-output-pi.test.js",
  "tests/secureshop/vuln/chains/rag-summarizer-supervisor.test.js",
  "tests/secureshop/vuln/llm/llm01-direct-pi.test.js",
  "tests/secureshop/vuln/llm/llm01-indirect-pi-audit-log.test.js",
  "tests/secureshop/vuln/llm/llm01-indirect-pi-product.test.js",
  "tests/secureshop/vuln/llm/llm01-indirect-pi-review.test.js",
  "tests/secureshop/vuln/llm/llm01-pi-email.test.js",
  "tests/secureshop/vuln/llm/llm01-pi-file-upload.test.js",
  "tests/secureshop/vuln/llm/llm02-analytics-pii-leak.test.js",
  "tests/secureshop/vuln/llm/llm02-sensitive-info.test.js",
  "tests/secureshop/vuln/llm/llm02-user-lookup.test.js",
  "tests/secureshop/vuln/llm/llm04-policy-poisoning-merchant.test.js",
  "tests/secureshop/vuln/llm/llm04-policy-poisoning.test.js",
  "tests/secureshop/vuln/llm/llm04-rag-competitor-poisoning.test.js",
  "tests/secureshop/vuln/llm/llm04-rag-poisoning.test.js",
  "tests/secureshop/vuln/llm/llm05-improper-output.test.js",
  "tests/secureshop/vuln/llm/llm05-listing-xss.test.js",
  "tests/secureshop/vuln/llm/llm06-excessive-agency-e2e.test.js",
  "tests/secureshop/vuln/llm/llm06-excessive-agency.test.js",
  "tests/secureshop/vuln/llm/llm07-admin-system-prompt-leak.test.js",
  "tests/secureshop/vuln/llm/llm07-system-prompt-leak.test.js",
  "tests/secureshop/vuln/llm/llm08-embedding-inversion.test.js",
  "tests/secureshop/vuln/llm/llm08-embedding-poisoning.test.js",
  "tests/secureshop/vuln/llm/llm09-misinformation.test.js",
  "tests/secureshop/vuln/llm/llm09-pricing-hallucination.test.js",
  "tests/secureshop/vuln/llm/llm10-analytics-unbounded.test.js",
  "tests/secureshop/vuln/llm/llm10-audit-unbounded.test.js",
  "tests/secureshop/vuln/llm/llm10-unbounded.test.js",
  "tests/secureshop/vuln/mcp/llm03-supply-chain.test.js",
  "tests/secureshop/vuln/mcp/mcp01-tool-poisoning.test.js",
  "tests/secureshop/vuln/mcp/mcp02-rug-pull.test.js",
  "tests/secureshop/vuln/mcp/mcp05-pi-via-tool-output.test.js",
  "tests/secureshop/vuln/mcp/mcp08-ssrf.test.js",
  "tests/secureshop/vuln/mcp/mcp09-impersonation.test.js",
  "tests/secureshop/vuln/mcp/xxe-import-manifest.test.js",
  "tests/secureshop/vuln/parity/llm04-rag-poisoning.parity.test.js",
  "tests/secureshop/vuln/parity/llm06-excessive-agency-e2e.parity.test.js",
  "tests/secureshop/vuln/parity/path-traversal-read-config.parity.test.js",
  "tests/secureshop/vuln/parity/sqli-union.parity.test.js",
  "tests/secureshop/vuln/parity/ssrf-return-policy.parity.test.js",
  "tests/secureshop/vuln/parity/xss-stored-listing.parity.test.js",
  "tests/secureshop/vuln/web/broken-access-inventory.test.js",
  "tests/secureshop/vuln/web/command-injection-image-optimize.test.js",
  "tests/secureshop/vuln/web/email-header-injection.test.js",
  "tests/secureshop/vuln/web/file-upload-extension-bypass.test.js",
  "tests/secureshop/vuln/web/file-upload-polyglot-rce.test.js",
  "tests/secureshop/vuln/web/file-upload-svg-xss.test.js",
  "tests/secureshop/vuln/web/html-injection.test.js",
  "tests/secureshop/vuln/web/idor-cart.test.js",
  "tests/secureshop/vuln/web/idor-inbox.test.js",
  "tests/secureshop/vuln/web/idor-order-status.test.js",
  "tests/secureshop/vuln/web/insecure-deser-listing-import.test.js",
  "tests/secureshop/vuln/web/path-traversal-upload.test.js",
  "tests/secureshop/vuln/web/sqli-blind-boolean.test.js",
  "tests/secureshop/vuln/web/sqli-coupon.test.js",
  "tests/secureshop/vuln/web/sqli-error-based.test.js",
  "tests/secureshop/vuln/web/sqli-nl-generated.test.js",
  "tests/secureshop/vuln/web/sqli-time-based.test.js",
  "tests/secureshop/vuln/web/sqli-union.test.js",
  "tests/secureshop/vuln/web/ssrf-competitor.test.js",
  "tests/secureshop/vuln/web/ssrf-email-inline-image.test.js",
  "tests/secureshop/vuln/web/ssrf-listing-import.test.js",
  "tests/secureshop/vuln/web/ssrf-return-policy.test.js",
  "tests/secureshop/vuln/web/ssti-listing-template.test.js",
  "tests/secureshop/vuln/web/ssti-policy-template.test.js",
  "tests/secureshop/vuln/web/xss-reflected-search.test.js",
  "tests/secureshop/vuln/web/xss-stored-email.test.js",
  "tests/secureshop/vuln/web/xss-stored-listing.test.js",
  "tests/secureshop/vuln/web/xss-stored-ticket.test.js",
  "tests/secureshop/vuln/web/xxe-import-bulk.test.js"
], 'nativePg', "Uses admitted disposable PostgreSQL fixtures or the native parity harness.");

const nativeBrowser = rows([
  "tests/secureshop/vuln/web/xss-stored-review.test.js"
], 'nativeBrowser', "PostgreSQL stored review plus pinned browser; supersedes the legacy browser-only dispatch.");

const disabledActualModel = rows([
  "tests/secureshop/vuln/llm/llm06-real-jailbreak.test.js"
], 'disabledActualModel', "Actual-model opt-in is disabled in this controlled native cohort; truthful skip required, no model acceptance.");

const controlledOnly = rows([
  "tests/secureshop/vuln/mcp/mcp06-credential-leak.test.js",
  "tests/secureshop/vuln/web/auth-bypass-jwt-none.test.js",
  "tests/secureshop/vuln/web/command-injection-restart.test.js",
  "tests/secureshop/vuln/web/path-traversal-read-config.test.js",
  "tests/secureshop/vuln/web/rce-run-diagnostic.test.js"
], 'controlledOnly', "Resource-free controlled proof may run in either cohort; remains in controlled discovery.");

const fixtureContract = rows([
  "tests/secureshop/vuln/fixturePgContract.test.js"
], 'fixtureContract', "Pre-connection fixture admission contracts remain in controlled discovery, excluded from native execution.");

const nativeCohort = Object.freeze([...nativePg, ...nativeBrowser, ...disabledActualModel, ...controlledOnly].sort((a, b) => a.file.localeCompare(b.file)));
const deferredNative = Object.freeze([...schemaFirst, ...nativePg, ...nativeBrowser].sort((a, b) => a.file.localeCompare(b.file)));
const all = Object.freeze([...schemaFirst, ...nativeCohort, ...fixtureContract]);

function validateRegistry(source) {
  const root = fs.realpathSync(source);
  const seen = new Set();
  for (const row of all) {
    if (seen.has(row.file)) throw new Error(`Duplicate native SecureShop registration: ${row.file}`);
    seen.add(row.file);
    const file = fs.realpathSync(path.join(root, row.file));
    if (!file.startsWith(`${root}${path.sep}`) || !fs.statSync(file).isFile()) throw new Error(`Invalid native SecureShop registration: ${row.file}`);
  }
  const actual = fs.readdirSync(path.join(root, 'tests/secureshop/vuln'), { recursive: true, withFileTypes: true })
    .filter(entry => entry.isFile() && entry.name.endsWith('.test.js'))
    .map(entry => path.relative(root, path.join(entry.parentPath, entry.name)).split(path.sep).join('/')).sort();
  const expected = all.filter(row => row.file.startsWith('tests/secureshop/vuln/')).map(row => row.file).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('SecureShop vulnerability test inventory changed; explicitly register every new or retired test before dispatch');
  return all;
}

function partitionSecureShopTests(files) {
  const native = new Map(deferredNative.map(row => [row.file, row]));
  return { files: files.filter(file => !native.has(file)), deferred: files.filter(file => native.has(file)).map(file => native.get(file)) };
}

module.exports = Object.freeze({ launcher, command, schemaFirst, nativePg, nativeBrowser, disabledActualModel, controlledOnly, fixtureContract, nativeCohort, deferredNative, validateRegistry, partitionSecureShopTests });

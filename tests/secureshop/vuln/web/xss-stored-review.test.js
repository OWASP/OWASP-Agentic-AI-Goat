'use strict';

/**
 * @intentional-vulnerability xss-stored-review
 * @teaches OWASP-Web:A03
 *
 * Actual ReviewCard render plus isolated browser execution; storage is a
 * disposable fixture database and no application server is used.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const Module = require('node:module');
const puppeteer = require('puppeteer');
const { seedShop } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

test('xss-stored-review: review body reaches the documented innerHTML sink and executes', { timeout: 30000 }, async t => {
  const fixture = await seedShop();
  let browserRetired = true;
  t.after(async () => { await fixture.close(); });
  const payload = '<img src="invalid://review" onerror="window.__storedReviewExecuted = true">';
  const inserted = await fixture.query(
    `INSERT INTO secureshop.reviews(product_id, author_id, body, rating, status)
     VALUES($1, $2, $3, $4, $5) RETURNING id`,
    [1, 2, payload, 5, 'approved'],
  );
  const { rows: [storedReview] } = await fixture.query(
    `SELECT * FROM secureshop.reviews WHERE id = $1`, [inserted.rows[0].id],
  );

  const clientRoot = path.join(REPO, 'client');
  const swc = require(path.join(clientRoot, 'node_modules/@swc/core'));
  const componentPath = path.join(clientRoot, 'src/pages/secureshop/components/ReviewCard.jsx');
  const transformed = swc.transformFileSync(componentPath, {
    swcrc: false, configFile: false,
    jsc: { parser: { syntax: 'ecmascript', jsx: true }, target: 'es2022',
      transform: { react: { runtime: 'automatic' } } },
    module: { type: 'commonjs' },
  });
  const compiled = new Module(componentPath);
  compiled.filename = componentPath;
  compiled.paths = Module._nodeModulePaths(path.dirname(componentPath));
  const nativeRequire = compiled.require.bind(compiled);
  compiled.require = request => request === './Rating.jsx' || request === './Badge.jsx'
    ? { __esModule: true, default: () => null }
    : nativeRequire(request);
  compiled._compile(transformed.code, componentPath);
  const ReviewCard = compiled.exports.default;
  const React = require(path.join(clientRoot, 'node_modules/react'));
  const { renderToStaticMarkup } = require(path.join(clientRoot, 'node_modules/react-dom/server'));
  const markup = renderToStaticMarkup(React.createElement(ReviewCard, { review: storedReview }));
  assert.match(markup, /__storedReviewExecuted/);

  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  assert.ok(executablePath && path.isAbsolute(executablePath), 'Native owner must admit an installed browser');
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-review-browser-'));
  browserRetired = false;
  const browser = await puppeteer.launch({ headless: true, executablePath, userDataDir, timeout: 15000, protocolTimeout: 15000 });
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    await page.setContent(markup, { timeout: 10000 });
    await page.waitForFunction(() => window.__storedReviewExecuted === true);
    assert.equal(await page.evaluate(() => window.__storedReviewExecuted), true);
  } finally {
    let timer;
    try { await Promise.race([browser.close().then(() => { browserRetired = true; }), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Owned review browser close timed out')), 5000); })]); } finally { clearTimeout(timer); }
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
});

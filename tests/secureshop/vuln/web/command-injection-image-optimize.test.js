const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability command-injection-image-optimize
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/optimize_images.js
 * The image_url is concatenated straight into a shell string passed to
 * child_process.exec. A merchant who sets image_url to
 *   thing.jpg; touch /tmp/pwn.txt
 * will have both commands dispatched. We assert the constructed cmd
 * contains the injection payload; execution is guarded by
 * SS_LISTING_ALLOW_EXEC=false in tests so we don't actually touch disk.
 */
test('command-injection-image-optimize: shell command carries the injection payload verbatim', async () => {
  const s = await seedShop();
  const previousAllowExec = process.env.SS_LISTING_ALLOW_EXEC;
  purgeToolCaches();
  try {
    // Update product image_url to carry a command-injection payload.
    await s.query(`UPDATE secureshop.products SET image_url = $1 WHERE id = $2`, ['thing.jpg; echo pwned-by-cmdi', 1]);

    process.env.SS_LISTING_ALLOW_EXEC = 'false';
    const { optimize_images } = require(path.join(REPO, 'agent-host/agents/listing/tools/optimize_images.js'));
    const r = await optimize_images({ product_id: 1 });
    assert.equal(r.ok, true);
    assert.match(r.cmd, /; echo pwned-by-cmdi/, 'injection payload survived into shell command string');
    assert.equal(r.executed, false, 'exec guarded in test');
  } finally {
    if (previousAllowExec === undefined) delete process.env.SS_LISTING_ALLOW_EXEC;
    else process.env.SS_LISTING_ALLOW_EXEC = previousAllowExec;
    await s.close();
  }
});

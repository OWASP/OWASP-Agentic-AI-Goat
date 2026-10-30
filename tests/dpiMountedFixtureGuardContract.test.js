'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const fixturePath = path.join(__dirname, 'postgres', 'dpiLiveWorkflow.integration.test.js');
const fixture = fs.readFileSync(fixturePath, 'utf8');

function exactlyOnce(needle) {
  const first = fixture.indexOf(needle);
  assert.notEqual(first, -1, `missing fixture contract: ${needle}`);
  assert.equal(fixture.indexOf(needle, first + needle.length), -1, `duplicate fixture contract: ${needle}`);
  return first;
}

test('mounted DPI fixture registers its exact listening origin before the first local request', () => {
  const listen = exactlyOnce("app.listen(0,'127.0.0.1'");
  const base = exactlyOnce("const base=`http://127.0.0.1:${server.address().port}`");
  const register = exactlyOnce('globalThis.__OWASP_AI_GOAT_DPI_REGISTER_OWNED_ORIGIN?.(base)');
  const firstRequest = fixture.indexOf('fetch(base+');

  assert.notEqual(firstRequest, -1, 'fixture must issue a local mounted request');
  assert.ok(listen < base, 'the origin must be derived only after the server starts listening');
  assert.ok(base < register, 'the exact derived origin must exist before registration');
  assert.ok(register < firstRequest, 'owned-origin registration must precede the first local request');
});

test('trace repair preserves donor receipt evidence and changes only the durable source event type', () => {
  assert.equal(fixture.includes("event.node==='judge_compare_source_validate'&&event.type==='decision'&&event.data.evidenceSummary==='trusted_server_reference_v1'"), true);
  assert.equal(fixture.includes("event.type==='verdict'&&event.data.evidenceSummary==='trusted_server_reference_v1'"), false);
  assert.equal(fixture.includes('comparisonVersion:(typeof stored.result_json'), true);
  assert.equal(fixture.includes('comparisonStages:(typeof stored.result_json'), true);
});

test('mounted reset uses the bounded JSON POST contract admitted by the network guard', () => {
  exactlyOnce("const headersFor=(key,json=false)=>({'x-dpi-owner':key,authorization:`Bearer ${sessions.get(key).token}`,...(json?{'content-type':'application/json'}:{})})");
  assert.ok(fixture.includes("fetch(base+'/progress/reset',{method:'POST',headers:headersFor('a',true),body:'{}'})"));
});

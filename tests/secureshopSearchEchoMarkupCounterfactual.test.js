'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const clientRequire = createRequire(path.join(__dirname, '../client/package.json'));
const { parseFragment } = clientRequire('parse5');

// Static HTML parsing only: no DOM execution, browser, network, Judge or credit.
// These opposed cases establish the factual distinction in the V7 proposal;
// they do not establish that a configured model classifies it correctly.
const literal = '<img src=x onerror="alert(\'owned\')">';
const escaped = '&lt;img src=x onerror="alert(\'owned\')"&gt;';
const cases = Object.freeze([
  { name: 'literal handler remains an element', html: literal, handler: "alert('owned')" },
  { name: 'pre does not turn a literal handler into text',
    html: `<pre>${literal}</pre>`, handler: "alert('owned')" },
  { name: 'entity-escaped tag delimiters remain character data',
    html: escaped, text: literal },
  { name: 'pre containing entity-escaped markup still has no image element',
    html: `<pre>${escaped}</pre>`, text: literal },
  { name: 'numeric escaped tag delimiters remain character data',
    html: '&#60;img src=x onerror="alert(\'owned\')"&#62;', text: literal },
  { name: 'entities inside a real handler attribute do not escape the tag',
    html: '<img src=x onerror="alert(&quot;owned&quot;)">', handler: 'alert("owned")' },
  { name: 'ordinary reflected search text has no event handler',
    html: '<p>Results for: <b>blue shoes</b></p>', text: 'Results for: blue shoes' },
]);

function descendants(node) {
  return [node, ...(node.childNodes || []).flatMap(descendants)];
}

for (const example of cases) {
  test(example.name, () => {
    const nodes = descendants(parseFragment(example.html, { sourceCodeLocationInfo: true }));
    const images = nodes.filter(node => node.tagName === 'img');
    const handlers = nodes.flatMap(node => (node.attrs || [])
      .filter(attribute => attribute.name.startsWith('on')));
    if (example.handler) {
      assert.equal(images.length, 1);
      assert.deepEqual(handlers, [{ name: 'onerror', value: example.handler }]);
      const location = images[0].sourceCodeLocation;
      const originalTag = example.html.slice(location.startOffset, location.endOffset);
      assert.ok(originalTag.startsWith('<img '));
      // Preserve the serialized evidence. Decoding an attribute for this static
      // assertion never replaces the original echoHtml passed to the Judge.
      assert.ok(example.html.includes(originalTag));
    } else {
      assert.deepEqual(images, []);
      assert.deepEqual(handlers, []);
      assert.equal(nodes.filter(node => node.nodeName === '#text')
        .map(node => node.value).join(''), example.text);
    }
  });
}

test('v7 clarification is opt-in and preserves two independent model decisions and original citations', async () => {
  const E = require('../server/services/secureshopSearchEchoBrowserEvidence');
  const { fixture } = require('./secureshopSearchEchoBrowserEvidence.test');
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const f = fixture();
  const candidate = E.buildSearchEchoBrowserCandidate({ ...f, evidenceVersion: 7 });
  assert.ok(candidate);
  assert.deepEqual(candidate, E.buildSearchEchoBrowserCandidate({ ...f, evidenceVersion: 6 }));
  assert.deepEqual(E.buildSearchEchoBrowserCandidate(f),
    E.buildSearchEchoBrowserCandidate({ ...f, evidenceVersion: 1 }));
  assert.deepEqual(E.RUBRIC_V7.criteria[1], E.RUBRIC_V6.criteria[1]);
  assert.match(E.RUBRIC_V7.criteria[0].description, /Entity-escaped tag delimiters in HTML text/);
  assert.match(E.RUBRIC_V7.criteria[0].description, /inside <pre>/);
  const input = { rubric: { ...E.RUBRIC_V7, mode: 'vuln' }, ...candidate, execution: f.execution };
  assert.equal(E.isSearchEchoBrowserJudgeInputValid(input, f.qualifyModel), true);
  for (const decisions of [[true, true], [false, true], [true, false]]) {
    const observed = [];
    const judge = createObjectiveJudge({ model: { async chat(messages, _tools, options) {
      const record = JSON.parse(messages[1].content).evidence[0];
      const index = record.id === 'search_echo_source' ? 0 : 1;
      const quote = index === 0 ? record.content.echoHtml : record.content.execution;
      observed.push(record.id);
      assert.deepEqual(options.format.properties.citations.items.properties.quote.enum, [quote]);
      assert.equal(options.format.properties.satisfied.type, 'boolean');
      if (index === 0) {
        assert.equal(record.content.echoHtml, f.originalRead.echoHtml);
        assert.match(messages[0].content, /Entities inside a real handler attribute do not make that attribute inert/);
      }
      return { provider: 'controlled', model: 'controlled', mocked: false, fallback: false,
        response: JSON.stringify({ observation: 'Controlled independent semantic result; this test does not qualify actual model discrimination.',
          citations: [{ evidenceId: record.id, quote }], satisfied: decisions[index] }) };
    } } });
    const result = await E.createSearchEchoBrowserJudgeGuard(judge, f.qualifyModel)(input);
    assert.deepEqual(observed, ['search_echo_source', 'search_echo_execution_observation']);
    assert.deepEqual(result.criteria.map(c => c.satisfied), decisions);
    assert.equal(result.verdict, decisions.every(Boolean) ? 'pass' : 'fail');
  }
});

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createLegacySensitiveTools } = require('../server/services/legacySensitiveTools');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-legacy-sensitive-tools-'));
  const publicDir = path.join(root, 'public');
  fs.mkdirSync(publicDir);
  fs.mkdirSync(path.join(root, 'secret'));
  fs.writeFileSync(path.join(publicDir, 'welcome.txt'), 'Welcome');
  fs.writeFileSync(path.join(root, 'secret', 'flag.txt'), 'FLAG: fixture-sensitive-value');
  fs.writeFileSync(path.join(root, 'secret', 'template.txt'), 'Key: <!--#echo var="API_KEY" -->');
  const tools = createLegacySensitiveTools({ sensitiveFilesDir: root, publicDir,
    now: () => new Date('2026-09-14T00:00:00Z') });
  return { root, publicDir, tools };
}

test('teaching-file reader preserves the mapped traversal and records the real boundary', t => {
  const { root, tools } = fixture(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = tools.readTeachingFile({ path: '../secret/flag.txt' });
  assert.equal(result.success, true);
  assert.equal(result.content, 'FLAG: fixture-sensitive-value');
  assert.equal(result.boundary.outsidePublic, true);
  assert.equal(result.boundary.resolvedTarget, fs.realpathSync(path.join(root, 'secret', 'flag.txt')));
  assert.deepEqual(tools.readTeachingFile({ path: 'missing.txt' }), {
    success: false, path: 'missing.txt', error: 'File not found'
  });
});

test('teaching reader rejects lexical and symlink escapes without reading host bytes', t => {
  const { root, tools } = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-legacy-sensitive-outside-'));
  t.after(() => { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); });
  fs.writeFileSync(path.join(outside, 'private.txt'), 'host-private-fixture');
  fs.symlinkSync(path.join(outside, 'private.txt'), path.join(root, 'public', 'escape.txt'));
  const lexical = tools.readTeachingFile({ path: '../../../outside-private.txt' });
  const symlink = tools.readTeachingFile({ path: 'escape.txt' });
  assert.equal(lexical.success, false);
  assert.equal(lexical.code, 'TEACHING_PATH_OUTSIDE_ROOT');
  assert.equal(symlink.success, false);
  assert.equal(symlink.code, 'TEACHING_PATH_OUTSIDE_ROOT');
  assert.doesNotMatch(JSON.stringify([lexical, symlink]), /host-private-fixture/);
});

test('documented root aliases resolve to the same owned teaching file', t => {
  const { root, tools } = fixture(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.equal(tools.readTeachingFile({ path: '../secret/flag.txt' }).content, 'FLAG: fixture-sensitive-value');
  assert.equal(tools.readTeachingFile({ path: 'secret/flag.txt' }).content, 'FLAG: fixture-sensitive-value');
  assert.equal(tools.readTeachingFile({ path: '/secret/flag.txt' }).content, 'FLAG: fixture-sensitive-value');
  assert.equal(tools.readTeachingFile({ path: 'welcome.txt' }).content, 'Welcome');
  assert.equal(tools.readTeachingFile({ path: 'public/welcome.txt' }).content, 'Welcome');
});

test('SSI interpreter performs mapped echo/include effects while command output stays explicitly simulated', t => {
  const { root, tools } = fixture(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = tools.renderSsiTemplate({
    template: '<!--#echo var="API_KEY" -->|<!--#include file="secret/flag.txt" -->|<!--#exec cmd="whoami" -->',
    request: { ip: '127.0.0.1' },
  });
  assert.match(result.rendered, /sk-proj-abc123def456/);
  assert.match(result.rendered, /fixture-sensitive-value/);
  assert.match(result.rendered, /<pre>www-data<\/pre>/);
  assert.equal(result.executionMode, 'lab_ssi_interpreter');
  assert.equal(result.commandExecution, 'simulated');
  assert.match(result.warning, /no operating-system command was executed/);
  assert.deepEqual(result.directives, ['echo:API_KEY', 'include:secret/flag.txt', 'exec:whoami']);
});

test('combined teaching operation uses the same read and SSI observations', t => {
  const { root, tools } = fixture(); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const result = tools.processTeachingDocument({ path: '../secret/template.txt', processSsi: true });
  assert.equal(result.boundary.outsidePublic, true);
  assert.equal(result.original, 'Key: <!--#echo var="API_KEY" -->');
  assert.equal(result.rendered, 'Key: sk-proj-abc123def456');
  assert.equal(result.ssi.executionMode, 'lab_ssi_interpreter');
});
test('Fixed tools deny protected and symlinked files and never expand SSI', t => {
  const { root, publicDir, tools } = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.symlinkSync(path.join(root, 'secret', 'flag.txt'), path.join(publicDir, 'alias.txt'));
  for (const target of ['../secret/flag.txt', 'secret/flag.txt', 'alias.txt']) {
    const result = tools.readTeachingFile({ path: target, mode: 'fixed' });
    assert.equal(result.success, false);
    assert.equal(result.code, 'PUBLIC_FILE_ONLY');
    assert.doesNotMatch(JSON.stringify(result), /fixture-sensitive-value/);
  }
  assert.equal(tools.readTeachingFile({ path: 'welcome.txt', mode: 'fixed' }).content, 'Welcome');
  const template = '<!--#echo var="API_KEY" --> <!--#include file="secret/flag.txt" --> <!--#exec cmd="whoami" -->';
  const rendered = tools.renderSsiTemplate({ template, mode: 'fixed' });
  assert.equal(rendered.rendered, template);
  assert.equal(rendered.ssiSucceeded, false);
  assert.equal(rendered.commandExecution, 'none');
  assert.equal(rendered.executionMode, 'literal_template');
});

test('tool configuration cannot manufacture a public boundary outside its teaching root', t => {
  const { root, publicDir } = fixture();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-legacy-sensitive-config-'));
  t.after(() => { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); });
  fs.symlinkSync(outside, path.join(root, 'outside-public'));
  for (const invalidPublic of [outside, path.join(root, 'outside-public'), root]) {
    assert.throws(() => createLegacySensitiveTools({ sensitiveFilesDir: root, publicDir: invalidPublic }),
      { code: 'LEGACY_SENSITIVE_ROOT_INVALID' });
  }
  assert.throws(() => createLegacySensitiveTools({ sensitiveFilesDir: root, publicDir, fileBaseDir: outside }),
    { code: 'LEGACY_SENSITIVE_ROOT_INVALID' });
  assert.throws(() => createLegacySensitiveTools({ sensitiveFilesDir: root, publicDir: path.join(publicDir, 'welcome.txt') }),
    { code: 'LEGACY_SENSITIVE_ROOT_INVALID' });
  const tools = createLegacySensitiveTools({ sensitiveFilesDir: root, publicDir, fileBaseDir: root });
  assert.equal(tools.readTeachingFile({ path: 'public/welcome.txt' }).boundary.outsidePublic, false);
  assert.equal(tools.readTeachingFile({ path: 'secret/flag.txt' }).boundary.outsidePublic, true);
});

test('denied document processing produces gradeable negative evidence for all manual objectives', async t => {
  const { root, tools } = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  const { createLegacySensitiveObjectiveGrader } = require('../server/services/legacySensitiveObjectiveGrader');
  let calls = 0;
  const judge = createObjectiveJudge({ model: { async chat() {
    calls += 1;
    return { provider: 'controlled', model: 'fixture', response: JSON.stringify({ verdict: 'fail',
      explanation: 'The reader returned a denial; no protected content or SSI substitution occurred.',
      criteria: [{ id: 'observed_outcome', satisfied: false, evidenceRefs: ['tool_result'] }] }) };
  } } });
  const grader = createLegacySensitiveObjectiveGrader({ judge, postgres: false });
  for (const requestedPath of ['../../../outside.txt', 'missing.txt']) {
    const result = tools.processTeachingDocument({ path: requestedPath, processSsi: true });
    assert.equal(result.success, false);
    assert.equal(result.original, null);
    assert.equal(result.rendered, null);
    assert.equal(result.processedSsi, false);
    for (const objectiveId of ['path_traversal', 'ssi_injection', 'combined_traversal_ssi']) {
      const outcome = await grader.evaluate({ userId: 9, objectiveId, request: requestedPath, result,
        execution: { runId: '11111111-1111-4111-8111-111111111111', check: async () => {} } });
      assert.equal(outcome.judgment.verdict, 'fail');
      assert.equal(outcome.completed, false);
      assert.equal(outcome.durable, false);
    }
  }
  assert.equal(calls, 6);
});

test('rendering a filename does not load it; explicit read then render consumes actual file bytes', t => {
  const { root, tools } = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const filename = '../secret/template.txt';
  const mistaken = tools.renderSsiTemplate({ template: filename });
  assert.equal(mistaken.original, filename);
  assert.equal(mistaken.rendered, filename);
  assert.equal(mistaken.ssiDetected, false);
  const observed = tools.readTeachingFile({ path: filename });
  assert.equal(observed.success, true);
  const rendered = tools.renderSsiTemplate({ template: observed.content });
  assert.equal(rendered.original, fs.readFileSync(path.join(root, 'secret', 'template.txt'), 'utf8'));
  assert.equal(rendered.rendered, 'Key: sk-proj-abc123def456');
  assert.equal(rendered.ssiDetected, true);
  assert.equal(rendered.commandExecution, 'none');
});


test('SSI includes preserve literal replacement tokens from actual file bytes', t => {
  const { root, tools } = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = "literal $& $$ $` $' end";
  fs.writeFileSync(path.join(root, 'secret', 'literal.txt'), bytes);
  const template = 'before <!--#include file="secret/literal.txt" --> after';
  assert.equal(tools.renderSsiTemplate({ template }).rendered, `before ${bytes} after`);
  fs.writeFileSync(path.join(root, 'secret', 'literal-template.txt'), template);
  assert.equal(tools.processTeachingDocument({ path: '../secret/literal-template.txt', processSsi: true }).rendered,
    `before ${bytes} after`);
});


test('SSI simulated command output preserves literal replacement tokens and discloses simulation', t => {
  const { root, tools } = fixture();
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const command = "show $& $$ $` $'";
  const result = tools.renderSsiTemplate({ template: `before <!--#exec cmd="${command}" --> after` });
  assert.equal(result.rendered, `before <pre>Command executed: ${command}\n[Output simulated for security]</pre> after`);
  assert.equal(result.commandExecution, 'simulated');
  assert.match(result.warning, /no operating-system command was executed/);
});


test('manual SSI grading requires a successful real directive even with a permissive Judge', async t => {
 const { root, tools } = fixture();
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 const { createLegacySensitiveObjectiveGrader } = require('../server/services/legacySensitiveObjectiveGrader');
 const { observedFacts } = require('../server/agent-runtime/legacySensitiveEvidence');
 const grader = createLegacySensitiveObjectiveGrader({ postgres: false, judge: async () => ({ verdict: 'pass' }) });
 const cases = [
  ['<!--#include file="missing.txt" -->', false],
  ['<!--#echo var="UNKNOWN" -->', false],
  ['<!--#exec cmd="whoami" -->', false],
  ['<!--#echo var="API_KEY" -->', true],
  ['<!--#include file="secret/flag.txt" -->', true],
  ['<!--#include file="missing.txt" --> <!--#echo var="API_KEY" -->', true],
 ];
 for (const [template, expected] of cases) {
  const result = tools.renderSsiTemplate({ template });
  assert.equal(observedFacts('ssi_injection', result).observed_effect, expected, template);
  const outcome = await grader.evaluate({ userId: 9, objectiveId: 'ssi_injection', request: template, result,
   execution: { runId: '11111111-1111-4111-8111-111111111111', check: async () => {} } });
  assert.equal(outcome.completed, expected, template);
 }
});


test('combined credit requires a real SSI effect as well as protected flag disclosure', async t => {
 const { root, tools } = fixture();
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 const { createLegacySensitiveObjectiveGrader } = require('../server/services/legacySensitiveObjectiveGrader');
 const { FILE_FLAGS } = require('../server/config/legacySensitiveFlags');
 const grader = createLegacySensitiveObjectiveGrader({ postgres: false, judge: async () => ({ verdict: 'pass' }) });
 for (const [directive, expected] of [['<!--#echo var="UNKNOWN" -->', false], ['<!--#include file="missing.txt" -->', false], ['<!--#echo var="API_KEY" -->', true]]) {
  fs.writeFileSync(path.join(root, 'secret', 'combined.txt'), `${FILE_FLAGS[0]} ${directive}`);
  const result = tools.processTeachingDocument({ path: '../secret/combined.txt', processSsi: true });
  const outcome = await grader.evaluate({ userId: 9, objectiveId: 'combined_traversal_ssi', request: '../secret/combined.txt', result,
   execution: { runId: '11111111-1111-4111-8111-111111111111', check: async () => {} } });
  assert.equal(outcome.completed, expected, directive);
 }
});


test('production Judge rejects attempted pass on failed manual SSI evidence and accepts grounded resolution', async t => {
 const { root, tools } = fixture();
 t.after(() => fs.rmSync(root, { recursive: true, force: true }));
 const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
 const { createLegacySensitiveObjectiveGrader } = require('../server/services/legacySensitiveObjectiveGrader');
 let calls = 0;
 const judge = createObjectiveJudge({ model: { async chat() {
  calls += 1;
  return { provider: 'controlled', model: 'fixture', response: JSON.stringify({ verdict: 'pass',
   explanation: 'The controlled model asserts success.',
   criteria: [{ id: 'observed_outcome', satisfied: true, evidenceRefs: ['tool_result'] }] }) };
 } } });
 const grader = createLegacySensitiveObjectiveGrader({ postgres: false, judge });
 for (const [template, expected] of [['<!--#include file="missing.txt" -->', false], ['<!--#echo var="UNKNOWN" -->', false], ['<!--#exec cmd="whoami" -->', false], ['<!--#echo var="API_KEY" -->', true]]) {
  const before = calls;
  const outcome = await grader.evaluate({ userId: 9, objectiveId: 'ssi_injection', request: template,
   result: tools.renderSsiTemplate({ template }),
   execution: { runId: '11111111-1111-4111-8111-111111111111', check: async () => {} } });
  assert.ok(calls > before, 'production Judge invoked the controlled transport');
  assert.equal(outcome.completed, expected, template);
  assert.equal(outcome.judgment.verdict, expected ? 'pass' : 'inconclusive', template);
 }
});

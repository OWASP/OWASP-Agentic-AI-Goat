'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const main = require('./fixtures/dpiSpanCalibrationMain');
const calibration = require('./fixtures/dpiSpanCalibration');

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const identity = Object.freeze({ model: 'llama3.1:8b', digest: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e' });

function admission(candidatePin, basePin) {
  return {
    version: 'dpi-side-compact-conjunction-v24-calibration-v1',
    inputSha256: main.SELECTED_V6_SHA,
    sourceProtocol: 'dpi-side-selected-semantic6-v1',
    protocol: 'dpi-side-compact-conjunction-v9',
    candidatePath: main.COMPACT_CONJUNCTION_V9_PATH,
    candidateSha256: candidatePin,
    baseProtocol: 'dpi-side-conjunction-v8',
    baseCandidatePath: main.CONJUNCTION_V8_PATH,
    baseCandidateSha256: basePin,
    contextTokens: 20480,
    providerTimeoutMs: 180000,
    transportTimeoutMs: 180000,
    reusedCorpus: true,
    changedProtocol: true,
    labelsExternal: true,
    actorProof: false,
    creditProof: false,
  };
}

test('v24 current-8B budget stays fixed while the historical six-case source denies policy drift', () => {
  const cfg = main.settings({ DPI_SPAN_PROFILE: main.COMPACT_CONJUNCTION_V9_8B_PROFILE });
  assert.deepEqual(cfg, { profile: 'semantic-side-compact-conjunction-v24-8b', input: main.SELECTED_V6_INPUT,
    inputSha: main.SELECTED_V6_SHA, records: 6, calls: 12, workMs: 2220000, externalMs: 180000 });
  assert.deepEqual(calibration.profileFor(main.COMPACT_CONJUNCTION_V9_8B_PROFILE), {
    protocols: ['dpi-side-compact-conjunction-v9'], cases: 6, calls: 12, contextTokens: 20480,
  });
  const frozen = JSON.parse(fs.readFileSync(main.SELECTED_V6_INPUT));
  const policyPath = 'server/agent-runtime/dpiPolicyContract.js';
  const historicalPin = '2ebaa0805844b4559e3a85c8c8b7fce868a257e91df35df96b289ab437e068dd';
  const drift = frozen.contracts.filter(row => sha(fs.readFileSync(row.path)) !== row.sha256);
  assert.deepEqual(drift.map(row => row.path), [policyPath]);
  assert.equal(drift[0].sha256, historicalPin);
  const currentPin = sha(fs.readFileSync(policyPath));
  assert.throws(() => main.projectSelectedV6(frozen), error =>
    error?.code === 'ERR_ASSERTION' && error.actual === currentPin && error.expected === historicalPin);
  const rows = frozen.cases;
  assert.equal(rows.length, 6);
  assert.ok(rows.every(row => row.objective === 'side_stepping'));
  assert.deepEqual(main.admitJudgeSelection(main.COMPACT_CONJUNCTION_V9_8B_PROFILE,
    { defaultJudgeIdentity: identity }, {}), identity);
  for (const [manifest, env] of [[{}, {}], [{ defaultJudgeIdentity: identity, judgeIdentity: identity }, {}],
    [{ defaultJudgeIdentity: identity }, { DPI_SPAN_JUDGE_MODEL: identity.model }]]) {
    assert.throws(() => main.admitJudgeSelection(main.COMPACT_CONJUNCTION_V9_8B_PROFILE, manifest, env));
  }
});

test('v24 calibration admission binds candidate, v8 base, default 8B, and non-credit scope', () => {
  const candidatePin = sha(fs.readFileSync(main.COMPACT_CONJUNCTION_V9_PATH));
  const basePin = sha(fs.readFileSync(main.CONJUNCTION_V8_PATH));
  const cfg = main.settings({ DPI_SPAN_PROFILE: main.COMPACT_CONJUNCTION_V9_8B_PROFILE });
  const pins = new Map([[main.COMPACT_CONJUNCTION_V9_PATH, candidatePin], [main.CONJUNCTION_V8_PATH, basePin]]);
  const expected = admission(candidatePin, basePin);
  assert.deepEqual(main.compactConjunctionAdmission({ sideCompactAdmission: expected }, pins, cfg), expected);
  for (const [key, value] of [['protocol', 'wrong'], ['contextTokens', 32768], ['reusedCorpus', false],
    ['changedProtocol', false], ['labelsExternal', false], ['actorProof', true], ['creditProof', true]]) {
    assert.throws(() => main.compactConjunctionAdmission({ sideCompactAdmission: { ...expected, [key]: value } }, pins, cfg));
  }
  assert.throws(() => main.compactConjunctionAdmission({ sideCompactAdmission: expected, regressionAdmission: {} }, pins, cfg));
});

test('native supervisor exposes the exact closed v24 profile and admission', () => {
  const probe = `import importlib.util,json\nfrom pathlib import Path\nfrom types import SimpleNamespace\np=Path(${JSON.stringify(process.cwd())})/'tests/postgres/run-rag-whole-evidence-v5-main.py'\ns=importlib.util.spec_from_file_location('side_compact_v24',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nc=m.profile(SimpleNamespace(profile='dpi-side-compact-conjunction6-8b'))\ncp='server/agent-runtime/dpiSideCompactConjunctionCandidate.js';bp='server/agent-runtime/dpiSideConjunctionCandidate.js'\nr={'version':'dpi-side-compact-conjunction-v24-calibration-v1','inputSha256':c['sha'],'sourceProtocol':'dpi-side-selected-semantic6-v1','protocol':'dpi-side-compact-conjunction-v9','candidatePath':cp,'candidateSha256':'a'*64,'baseProtocol':'dpi-side-conjunction-v8','baseCandidatePath':bp,'baseCandidateSha256':'b'*64,'contextTokens':20480,'providerTimeoutMs':180000,'transportTimeoutMs':180000,'reusedCorpus':True,'changedProtocol':True,'labelsExternal':True,'actorProof':False,'creditProof':False}\nmanifest={'files':[{'path':cp,'sha256':'a'*64},{'path':bp,'sha256':'b'*64}],'sideCompactAdmission':r,'defaultJudgeIdentity':{'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}}\nm.validate_regression_admission(manifest,c)\nm.judge_selection(SimpleNamespace(profile='dpi-side-compact-conjunction6-8b',judge_model=None,judge_model_digest=None),manifest)\nfor key,value in [('protocol','wrong'),('reusedCorpus',False),('creditProof',True)]:\n bad={**manifest,'sideCompactAdmission':{**r,key:value}}\n try:m.validate_regression_admission(bad,c);raise AssertionError(key)\n except ValueError:pass\nprint(json.dumps({**{k:c[k] for k in ('calls','seconds','childProfile','input','sha','expectations','expectationsSha')},'required':sorted(c['required'])}))`;
  const child = spawnSync('python3', ['-B', '-c', probe], { encoding: 'utf8' });
  assert.equal(child.status, 0, child.stderr);
  const value = JSON.parse(child.stdout);
  assert.equal(value.calls, 12); assert.equal(value.seconds, 2280);
  assert.equal(value.childProfile, main.COMPACT_CONJUNCTION_V9_8B_PROFILE);
  assert.equal(value.input, main.SELECTED_V6_INPUT); assert.equal(value.sha, main.SELECTED_V6_SHA);
  assert.match(value.expectations, /dpi-side-selected-semantic6-expectations-v1\.json$/);
  for (const file of [main.COMPACT_CONJUNCTION_V9_PATH, main.CONJUNCTION_V8_PATH,
    'server/agent-runtime/dpiSideSourceLinkCandidate.js', 'server/agent-runtime/dpiSelectedCompactContextCandidate.js',
    'server/agent-runtime/dpiSelectedResponseConsistencyPolicy.js']) assert.ok(value.required.includes(file));
});

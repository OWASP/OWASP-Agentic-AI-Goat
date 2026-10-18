'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ACL_FIXTURE_SHA256 = 'f7ae42fcafde8d2dc0a01ec44fe405ab90bb78cf696d16535dd35924347df519';
const ACL_QUALIFICATION_SCOPE = 'historical 0024 foundation and 0059 through 0100 migration successors; '
  + 'current v30 fresh/populated/noop, including retained historical receipts and all29 direct predecessor '
  + 'transitions with exact missing-key denials, preserved instructor overrides and enforcement, '
  + 'wrong-role snapshot rejection by the actual v30 guard, and exact receipt replay; '
  + '0097 product-search purpose admission, v29-to-v30 arithmetic-only denial, fresh customer-only defaults, runtime privilege and trigger '
  + 'guards, session/sibling/reset fences, and immutable audit/mail evidence; database-only, '
  + 'no model/browser/product search/listing/stock/price effect';
const PRICING_JOURNAL_FIXTURE_SHA256 = '90fbcce01cea934420f2a20c044896e35dca4e189ac4550ca56d8a0c4cf47e4a';
const V19_FIXTURE_SHA256 = '8853232007d6ab8289d7fe1ad7bf14952f729d5381b878d58feb63890a0212f3';

test('Pricing journal current-main plan allocates nothing and admits only its five disposable stores', () => {
  const root = path.resolve(__dirname, '..');
  const driver = 'tests/postgres/run-persona-transition-main-isolated.py';
  const plan = spawnSync('python3', ['-c', `import contextlib, hashlib, importlib.util, io, json, pathlib, sys, tempfile, subprocess
spec=importlib.util.spec_from_file_location('pricing_plan', '${driver}')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
def forbidden(*args, **kwargs): raise AssertionError('Plan attempted allocation or execution')
tempfile.mkdtemp=forbidden
subprocess.run=forbidden
pathlib.Path.mkdir=forbidden
launcher.sha=lambda path: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
sys.argv=['${driver}','--suite','pricing-journal','--plan']
assert launcher.main()==0`], {
    cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(plan.status, 0, plan.stderr);
  assert.deepEqual(JSON.parse(plan.stdout), {
    plan: true, suite: 'pricing-journal',
    fixture: 'tests/postgres/secureshopPricingJournal.integration.test.js',
    stores: [['IDENTITY', 'identity'], ['FRESH', 'secureshop_agents'],
      ['COMMERCE', 'secureshop'], ['ACLFRESH', 'secureshop_agents'], ['REVIEW', 'secureshop_review']],
    freshCohort: null, expectedTests: 1, sourceCopies: false, actualModel: false,
    allocationStarted: false, pricingCohort: 'blocked-denial',
    fixtureSha256: PRICING_JOURNAL_FIXTURE_SHA256,
  });
  const rejected = spawnSync('python3', [driver, '--suite', 'pricing-journal', '--fresh-cohort', 'historical-0015', '--plan'], {
    cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(rejected.status, 2);
  assert.match(rejected.stderr, /exclusive to persona-password/);
});

test('Pricing journal run wiring is closed, canonical, pinned and writes outside current source', () => {
  const root = path.resolve(__dirname, '..');
  const checked = spawnSync('python3', ['-c', `import ast, pathlib
tree=ast.parse(pathlib.Path('tests/postgres/run-persona-transition-main-isolated.py').read_text())
branch=next(node for node in ast.walk(tree) if isinstance(node,ast.If)
 and ast.unparse(node.test)=="args.suite == 'pricing-journal'"
 and any(isinstance(child,ast.Assign) and any(ast.unparse(target)=="env['PERSONA_PRICING_NATIVE']" for target in child.targets) for child in node.body))
values={ast.unparse(target):ast.literal_eval(node.value) if isinstance(node.value,ast.Constant) else ast.unparse(node.value)
 for node in branch.body if isinstance(node,ast.Assign) for target in node.targets}
assert values=={"env['DVAIA_ISOLATED_TEST_WORKSPACE']":'str(ROOT)',"env['DVAIA_PRICING_OWNED_OUTPUT_ROOT']":'str(workspace)',
 "env['PERSONA_PRICING_NATIVE']":'1',"env['PERSONA_PRICING_CANONICAL']":'1'}
cohort=next(child for child in branch.body if isinstance(child,ast.If))
assert ast.unparse(cohort.test)=="args.pricing_cohort == 'canonical-current'"
assert ast.unparse(cohort.body[0].value.func)=='env.pop'
assert ast.literal_eval(cohort.body[0].value.args[0])=='PERSONA_PRICING_BLOCKED_NATIVE'
assert ast.unparse(cohort.orelse[0].targets[0])=="env['PERSONA_PRICING_BLOCKED_NATIVE']"
assert ast.literal_eval(cohort.orelse[0].value)=='1'
assert next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NODE_SHA' for t in n.targets))=='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NODE' for t in n.targets))
assert node.value.args[0].value.endswith('/node-v26.10.0-darwin-arm64/bin/node')
allocation=next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and ast.unparse(n.func)=='tempfile.mkdtemp')
assert ast.unparse(next(k.value for k in allocation.keywords if k.arg=='dir'))=="None if args.suite == 'pricing-journal' else ROOT / 'tests/release-inputs'"
database=next(n.value for n in ast.walk(tree) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='database' for t in n.targets) and isinstance(n.value,ast.IfExp))
assert 'pricing-journal' in ast.literal_eval(database.test.comparators[0])
assert ast.unparse(database.body)=="'dvaia_test_persona_' + nonce[:12] + '_' + store.lower()"
source=pathlib.Path('tests/postgres/run-persona-transition-main-isolated.py').read_text()
assert "ROOT/'tests/fixtures/pricingOwnedOutput.js'" in source
assert "ROOT/'tests/fixtures/secureshopPricingJudgmentPersistence.js'" in source
assert 'PRICING_JOURNAL_FIXTURE_SHA256' in source
assert "pricingCohort=args.pricing_cohort or 'blocked-denial'" in source
assert "('skipped',0)" in source
`], { cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
  assert.equal(checked.status, 0, checked.stderr);
});

test('ACL main launcher retains its pinned no-copy v30 plan and exact qualification scope', () => {
  const root = path.resolve(__dirname, '..');
  const driver = 'tests/postgres/run-persona-transition-main-isolated.py';
  const plan = spawnSync('python3', [driver, '--suite', 'acl-foundation', '--plan'], {
    cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(plan.status, 0, plan.stderr);
  assert.deepEqual(JSON.parse(plan.stdout), {
    plan: true, suite: 'acl-foundation',
    fixture: 'tests/postgres/secureshopBoundAclFoundation.integration.test.js',
    stores: [['IDENTITY', 'identity'], ['FRESH', 'secureshop_agents'],
      ['COMMERCE', 'secureshop'], ['ACLFRESH', 'secureshop_agents']],
    freshCohort: null, expectedTests: 2, sourceCopies: false, actualModel: false,
    fixtureSha256: ACL_FIXTURE_SHA256,
    qualificationScope: ACL_QUALIFICATION_SCOPE,
  });
  const fixture = fs.readFileSync(path.join(root, 'tests/postgres/secureshopBoundAclFoundation.integration.test.js'), 'utf8');
  assert.equal(crypto.createHash('sha256').update(fixture).digest('hex'), ACL_FIXTURE_SHA256);
  assert.equal((fixture.match(/(?:t\.)?test\('/g) || []).length, 2);
  assert.match(fixture, /t\.test\('v30 runtime successor preserves populated v26 policy and denies its four newly applicable tools'/);
});

test('V19 seed plan is closed over two disposable identity stores and the reviewed fixture', () => {
  const root = path.resolve(__dirname, '..');
  const driver = 'tests/postgres/run-persona-transition-main-isolated.py';
  const plan = spawnSync('python3', [driver, '--suite', 'v19-assessment-seed', '--plan'], {
    cwd: root, encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });
  assert.equal(plan.status, 0, plan.stderr);
  assert.deepEqual(JSON.parse(plan.stdout), {
    plan: true, suite: 'v19-assessment-seed',
    fixture: 'tests/postgres/secureshopV19PendingCatalogSeed.integration.test.js',
    stores: [['FRESH', 'identity'], ['POPULATED', 'identity']],
    freshCohort: null, expectedTests: 2, sourceCopies: false, actualModel: false,
  });
  const fixture = fs.readFileSync(path.join(root, 'tests/postgres/secureshopV19PendingCatalogSeed.integration.test.js'));
  assert.equal(crypto.createHash('sha256').update(fixture).digest('hex'), V19_FIXTURE_SHA256);
});

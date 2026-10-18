'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');

test('CodeBot request journal is registered at its immutable qualified bytes with least runtime privilege', () => {
  const draft = read('docs/modernization/drafts/0053_codebot_request_journal.sql');
  const registered = read('db/postgres/identity-migrations/0053_codebot_request_journal.sql');
  assert.equal(registered, draft);
  assert.match(draft, /PRIMARY KEY\(owner_key,request_key_sha256\)/);
  assert.match(draft, /UNIQUE REFERENCES graph_runtime\.runs\(run_id\)/);
  assert.match(draft, /CHECK\(\(status='completed'\)=\(response_json IS NOT NULL\)\)/);
  assert.match(draft, /GRANT SELECT,INSERT .*dvaia_identity_runtime/);
  assert.match(draft, /GRANT UPDATE\(status,response_json,updated_at\)/);
  assert.match(draft, /REVOKE ALL .* FROM PUBLIC/);
  assert.doesNotMatch(draft, /GRANT (?:ALL|DELETE|TRUNCATE)/);
});

test('mounted qualifiers initialize the complete registered migration set and verify no-op replay', () => {
  const source = read('tests/postgres/codeBotLiveWorkflow.integration.test.js');
  assert.match(source, /assert\.deepEqual\(applied,fs\.readdirSync\(path\.join\(__dirname,'\.\.\/\.\.\/db\/postgres\/identity-migrations'\)\)\.filter\(f=>f\.endsWith\('\.sql'\)\)\.sort\(\)\)/);
  assert.match(source, /assert\.deepEqual\(await identityApi\.initializeIdentityRepository\(runtime, migration\), \[\]\)/);
  assert.equal(fs.existsSync(path.join(root,
    'db/postgres/identity-migrations/0050_mcp_conversation_history.sql')), true);
  assert.deepEqual([...Array(4)].map((_, index) => fs.existsSync(path.join(root,
    `db/postgres/identity-migrations/${String(index + 50).padStart(4, '0')}_${[
      'mcp_conversation_history', 'secureshop_mcp_trust', 'secureshop_controlled_ssrf', 'codebot_request_journal'][index]}.sql`))),
  [true, true, true, true]);
  assert.match(source, /same-key replay must not invoke the model again/);
  assert.match(source, /replay executes no additional tool effect/);
  assert.match(source, /replay executes no additional Judge evaluation/);
  assert.match(source, /a revoked session cannot retrieve its stored response/);
  assert.match(source, /earlier CodeBot generation/);
  assert.match(source, /SC_OBJECTIVE_IDS/);
  assert.match(source, /solutions\[objectiveId\]\.examples\[0\]\.prompt/);
  assert.match(source, /semanticFailures\.push/);
  assert.ok(source.indexOf('for (const objectiveId of SC_OBJECTIVE_IDS)')
    < source.indexOf("throw new AggregateError(semanticFailures"));
  assert.match(source, /skippedDependencies\.push\(\{ check: 'reset:sibling_progress_preservation'/);
  assert.match(source, /codebotIsolation, 'bwrap-codebot-v1'/);
});

test('deterministic mounted HTTP qualifier cannot claim model or effect qualification', () => {
  const source = read('tests/postgres/codeBotProductionHttp.integration.test.js');
  assert.match(source, /CODEBOT_WIRING_EVIDENCE_SCOPE, 'deterministic_http_only'/);
  assert.match(source, /actualModelCalls: 0/);
  assert.match(source, /effectQualification: false/);
  assert.match(source, /completed replay bypasses unavailable runner and scripted actor/);
  assert.match(source, /runner outage creates no request, effect, judgment, or completion/);
  assert.match(source, /revoked session receives no stored response/);
  assert.match(source, /reset fails before mutation while runner is down/);
  const launcher = read('tests/postgres/run-codebot-owned-workflow-isolated.py');
  assert.match(launcher, /parser\.add_argument\('--http-wiring-only'/);
  assert.match(launcher, /'CODEBOT_WIRING_EVIDENCE_SCOPE': 'deterministic_http_only'/);
  assert.match(launcher, /qualifier = \('tests\/postgres\/codeBotProductionHttp\.integration\.test\.js' if wiring/);
});

test('one-use launcher binds the exact grant and owns both disposable containers', () => {
  const source = read('tests/postgres/run-codebot-owned-workflow-isolated.py');
  assert.match(source, /EXPECTED_DOCKER = 'unix:\/\/\/Users\/averma5\/\.colima\/dvaia-pg-verify\/docker\.sock'/);
  assert.match(source, /grant\.get\('sourceHashes'\)/);
  assert.match(source, /set\(expected\) != set\(TRACKED\)/);
  assert.match(source, /consumerPid=os\.getpid\(\)/);
  assert.match(source, /actual exec session owner handle was not registered before Docker/);
  assert.ok(source.indexOf('register_owner();prepare_source(expected)') < source.indexOf("docker + ['run'"));
  assert.match(source, /REVIEWED_HIDDEN_TEACHING_FIXTURES\s*=\s*\([\s\S]*sidecars\/sandbox-runner\/labfs\/opt\/app\/config\/\.env/);
  assert.match(source, /for name in REVIEWED_HIDDEN_TEACHING_FIXTURES:[\s\S]*shutil\.copy2\(SOURCE \/ name, target\)/);
  assert.match(source, /missing = \[name for name in TRACKED if not \(workspace \/ name\)\.is_file\(\)\]/);
  assert.ok(source.indexOf('copied CodeBot source inventory is incomplete')
    < source.indexOf("for source, target in PREFIX.items():"));
  assert.match(source, /'postgres': f'dvaia-codebot-pg-/);
  assert.match(source, /'sandbox': f'dvaia-codebot-sandbox-/);
  assert.ok(source.indexOf("creation_attempted.add(containers['postgres'])")
    < source.indexOf("docker + ['run', '--detach', '--name', containers['postgres']"));
  assert.ok(source.indexOf("creation_attempted.add(containers['sandbox'])")
    < source.indexOf("docker + ['run', '--detach', '--name', containers['sandbox']"));
  assert.match(source, /'--security-opt', 'seccomp=unconfined'/);
  assert.match(source, /mount\.get\('Type'\) != 'tmpfs'/);
  assert.match(source, /expected_tmpfs = \{'\/var\/lib\/postgresql'\} if key == 'postgres' else set\(\)/);
  assert.match(source, /profile_name = f'dvaia-mcp-sandbox-\{suffix\}'/);
  assert.match(source, /render-mcp-sandbox-apparmor\.js/);
  assert.match(source, /'--security-opt', f'apparmor=\{profile_name\}'/);
  assert.doesNotMatch(source, /--cap-add/);
  assert.match(source, /apparmor_parser', '-R', remote_profile/);
  assert.match(source, /'remoteExactAbsent': remote_absent/);
  assert.match(source, /if not args\.readiness_only:[\s\S]*creation_attempted\.add\(containers\['postgres'\]\)/);
  assert.match(source, /gate\.protect_cleanup\(\)/);
  assert.match(source, /exact_absence\(name\)/);
  assert.match(source, /image_absence\(\)/);
  assert.match(source, /output\.flush\(\);os\.fsync\(output\.fileno\(\)\)/);
  assert.match(source, /def acquire_lock\(path, timeout=10\)/);
  assert.match(source, /capture_failure_diagnostics\(\)/);
  assert.match(source, /parser\.add_argument\('--readiness-only', action='store_true'\)/);
  assert.match(source, /'scope': 'strict_readiness'/);
  assert.ok(source.indexOf("if args.readiness_only:")
    < source.indexOf("for role in ('dvaia_identity_migration'"));
  assert.match(source, /docker \+ \['logs', '--tail', '200', name\]/);
  assert.match(source, /os\.chmod\(log_path, 0o600\)/);
  assert.doesNotMatch(source, /IDENTITY_DATABASE_URL.*os\.environ|private\.env/);
});

test('application scope IDs satisfy the unchanged real-sidecar allowlist', () => {
  const adapter = read('server/services/supplyChain/codeBotSandboxRuntime.js');
  const sidecar = read('sidecars/sandbox-runner/index.js');
  assert.match(adapter, /return `codebot-\$\{digest\}`/);
  assert.match(adapter, /values = \[scope\?\.platformOwnerId, scope\?\.platformSessionId, scope\?\.generation, scope\?\.runId\]/);
  assert.match(sidecar, /\^codebot-\[a-f0-9\]\{32\}\$/);
});

const {verifyImageJavaScript}=require('./fixtures/dockerJavaScriptClosure');
test('sandbox image copies every local JavaScript runtime dependency', () => {
 const files=verifyImageJavaScript(path.join(root,'sidecars/sandbox-runner'),read('sidecars/sandbox-runner/Dockerfile'));
 assert(files.has('/app/mcpProtectedState.js'));
 assert(files.has('/server/services/secureshopPromptPolicyContract.js'));
 assert(files.has('/app/policy-render/assets/nunjucks-3.2.4.js'));
});
test('packaging closure ignores comments but rejects missing actual require',t=>{
 const dir=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'codebot-closure-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'main.js'),"// require('./commented')\n/* require('./also-commented') */\nconst text=\"require('./string-only')\";");
 assert.doesNotThrow(()=>verifyImageJavaScript(dir,'FROM node\nWORKDIR /app\nCOPY main.js ./'));
 fs.writeFileSync(path.join(dir,'main.js'),"module.exports=require('./missing');");
 assert.throws(()=>verifyImageJavaScript(dir,'FROM node\nWORKDIR /app\nCOPY main.js ./'),/missing.*absent/);
});
test('packaging closure resolves multi-source and remapped final-image destinations',t=>{
 const dir=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'codebot-remap-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'first.js'),"module.exports=require('./second');require('/external');");fs.writeFileSync(path.join(dir,'second.js'),"module.exports=require('../../server/contract');");fs.writeFileSync(path.join(dir,'contract.js'),'module.exports=1;');
 const image='FROM node AS builder\nCOPY contract.js /ignored.js\nFROM node\nWORKDIR /app/tasks\nCOPY first.js second.js ./\nCOPY ["contract.js", "/server/contract.js"]';
 const files=verifyImageJavaScript(dir,image);assert(!files.has('/ignored.js'));assert(files.has('/app/tasks/second.js'));assert(files.has('/server/contract.js'));
 assert.throws(()=>verifyImageJavaScript(dir,image.replace('/server/contract.js','/elsewhere/contract.js')),/server\/contract/);
});

test('packaging closure resolves directory module main and ignores overwritten source bytes',t=>{
 const dir=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'codebot-module-main-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.mkdirSync(path.join(dir,'lib'));fs.writeFileSync(path.join(dir,'lib/package.json'),JSON.stringify({main:'entry.js'}));fs.writeFileSync(path.join(dir,'lib/entry.js'),'module.exports=1;');
 fs.writeFileSync(path.join(dir,'old.js'),"require('./not-copied');");fs.writeFileSync(path.join(dir,'main.js'),"require('./lib');");
 const image='FROM node\nWORKDIR /app\nCOPY old.js /app/main.js\nCOPY main.js /app/main.js\nCOPY lib ./lib';
 assert.doesNotThrow(()=>verifyImageJavaScript(dir,image));fs.unlinkSync(path.join(dir,'lib/entry.js'));assert.throws(()=>verifyImageJavaScript(dir,image),/dependency .\/lib is absent/);
});

test('strict readiness retains a bounded probe reason without model input', () => {
  const source = read('sidecars/sandbox-runner/index.js');
  assert.match(source, /strictProbe\.stderr\.toString\('utf8'\)[\s\S]*\.slice\(0, 512\)/);
  assert.match(source, /status: Number\.isInteger\(strictProbe\.status\)/);
  assert.match(source, /errorCode: typeof strictProbe\.error\?\.code/);
  assert.match(source, /codebotDiagnostic: CODEBOT_STRICT_AVAILABLE \? null : CODEBOT_STRICT_DIAGNOSTIC/);
});

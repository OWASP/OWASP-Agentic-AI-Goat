'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const helper = path.join(__dirname, 'postgres/mcp_owned_observed_action_rollout_safety.py');

test('every primary rollout failure attempts every independent restore and resume stage', () => {
  const script = String.raw`
import sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import attempt_all
primary=('managed-config-write','runner-replacement','backend-restart','authenticated-smoke')
for failed in primary:
 events=[]
 try:
  for stage in primary:
   events.append(stage)
   if stage==failed: raise RuntimeError(stage)
 except RuntimeError:
  def action(name,raises=False):
   def run():
    events.append(name)
    if raises: raise OSError(name)
    return True
   return run
  results,errors=attempt_all([
   ('restore-managed',action('restore-managed',True)),
   ('restore-image',action('restore-image')),
   ('restore-runner',action('restore-runner',True)),
   ('resume-processes',action('resume-processes')),
   ('recover-backend',action('recover-backend')),
   ('verify-preservation',action('verify-preservation',True)),
   ('remove-rollback-tag',action('remove-rollback-tag')),
  ])
  assert events[-7:]==['restore-managed','restore-image','restore-runner','resume-processes','recover-backend','verify-preservation','remove-rollback-tag']
  assert [e['stage'] for e in errors]==['restore-managed','restore-runner','verify-preservation']
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('terminal grant update and rollback image cleanup fail closed on stale identity or remaining tag', () => {
  const script = String.raw`
import sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import validate_terminal_grant,exact_image_absent
good={'grantId':'g','status':'consumed','owner':'o','ownerHandle':7,'consumerPid':11}
assert validate_terminal_grant(good,grant_id='g',owner='o',owner_handle=7,consumer_pid=11) is good
for field,value in [('grantId','x'),('owner','x'),('ownerHandle',8),('consumerPid',12),('status','granted')]:
 changed=dict(good);changed[field]=value
 try:validate_terminal_grant(changed,grant_id='g',owner='o',owner_handle=7,consumer_pid=11)
 except RuntimeError:pass
 else:raise AssertionError(field)
assert exact_image_absent(None) is True
try:exact_image_absent('sha256:remaining')
except RuntimeError:pass
else:raise AssertionError('remaining image accepted')
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('partial pause and resume failures retain only the process that still needs resuming', () => {
  const script = String.raw`
import signal,sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import RetryingPauseSet
events=[]; pauses=RetryingPauseSet()
pauses.stop(101,lambda pid,sig:events.append((pid,sig)))
try:pauses.stop(202,lambda _pid,_sig:(_ for _ in ()).throw(OSError('stop failed')))
except OSError:pass
else:raise AssertionError('failed stop accepted')
assert pauses.stopped==[101]
first=True
def resume(pid,sig):
 global first
 events.append((pid,sig))
 if first:
  first=False
  raise OSError('resume failed')
assert pauses.resume_all(resume)==[(101,'OSError')]
assert pauses.stopped==[101]
assert pauses.resume_all(resume)==[]
assert pauses.stopped==[]
assert events==[(101,signal.SIGSTOP),(101,signal.SIGCONT),(101,signal.SIGCONT)]
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('private client and logout validators keep smoke-session cleanup fail closed', () => {
  const script = String.raw`
import sys,urllib.request
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import private_cookie_opener,validate_logout_result,validate_revoked_status
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*_args):return None
client=private_cookie_opener(Redirect())
assert any(type(handler).__name__=='HTTPCookieProcessor' for handler in client.handlers)
assert validate_logout_result(200,{'success':True})
assert validate_revoked_status(401,{})
assert validate_revoked_status(200,{'authenticated':False})
for action in (
 lambda:validate_logout_result(200,{'success':False}),
 lambda:validate_logout_result(500,{'success':True}),
 lambda:validate_revoked_status(200,{'authenticated':True}),
):
 try:action()
 except RuntimeError:pass
 else:raise AssertionError('invalid session cleanup accepted')
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('dedicated source manifest denies stale actual-main qualification and validates synthetic binding', () => {
  const sourceRoot = path.resolve(__dirname, '..');
  const script = String.raw`
import pathlib,sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import load_exact_source_manifest
root=pathlib.Path(sys.argv[2]); relative=sys.argv[3]
import hashlib,json,tempfile
historical=json.loads((root/relative).read_text())['sourceHashes']
assert 'tests/postgres/run-mcp-owned-observed-action-rollout.py' in historical
assert 'tests/postgres/mcp_owned_observed_action_rollout_safety.py' in historical
# Bind the real main checkout to the immutable retained receipt. Drift denies
# this historical qualification; it must never be hidden by regenerated pins.
manifest_before=(root/relative).read_bytes()
actual={name:hashlib.sha256((root/name).read_bytes()).hexdigest() if (root/name).is_file() else None for name in historical}
drift={name for name in historical if historical[name]!=actual[name]}
assert drift, 'this retained historical qualification is expected to be stale'
for name in ('tests/postgres/run-mcp-owned-observed-action-rollout.py',
             'tests/postgres/mcp_owned_observed_action_rollout_safety.py'):
 assert actual[name]==historical[name], 'the unchanged preflight itself must remain pinned'
assert 'tests/mcpOwnedObservedActionRolloutSafety.test.js' in drift
try:load_exact_source_manifest(root,relative)
except FileNotFoundError as error:
 assert any(value is None for value in actual.values()), 'missing-source denial requires a retired source'
 assert pathlib.Path(error.filename) in {root/name for name,value in actual.items() if value is None}
except RuntimeError as error:assert str(error)=='observed-action rollout source changed'
else:raise AssertionError('stale historical source manifest accepted against actual main')
assert (root/relative).read_bytes()==manifest_before
# Synthetic data alone exercises successful binding and subsequent drift.
with tempfile.TemporaryDirectory() as directory:
 local=pathlib.Path(directory);(local/'value').write_text('before')
 digest=hashlib.sha256((local/'value').read_bytes()).hexdigest()
 (local/'manifest.json').write_text(json.dumps({'sourceHashes':{'value':digest}}))
 assert load_exact_source_manifest(local,'manifest.json')=={'value':digest}
 (local/'value').write_text('after')
 try:load_exact_source_manifest(local,'manifest.json')
 except RuntimeError:pass
 else:raise AssertionError('source drift accepted')
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper), sourceRoot,
    'docs/modernization/drafts/mcp-owned-observed-action-rollout-source-hashes.json'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('rollback retention keeps a pinned image until every recovery invariant is proven', () => {
  const script = String.raw`
import sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import rollback_retention_decision
keys=('oldImageRestored','serviceRestored','mailpitPreserved','targetVolumePreserved','privateConfigurationPreserved','applicationHealthy')
complete={key:True for key in keys}
assert rollback_retention_decision(complete,rollback_pinned=True,image_id='sha256:x')['remove'] is True
for key in keys:
 value=dict(complete);value[key]=False
 assert rollback_retention_decision(value,rollback_pinned=True,image_id='sha256:x')=={'remove':False,'retention':'required-present'}
try:rollback_retention_decision({},rollback_pinned=True,image_id=None)
except RuntimeError:pass
else:raise AssertionError('missing required rollback asset accepted')
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('owner handshake rejects a consumer PID and accepts a distinct unified execution session', () => {
  const script = String.raw`
import sys
sys.path.insert(0,sys.argv[1])
from mcp_owned_observed_action_rollout_safety import validate_owner_handle
assert validate_owner_handle('35017',consumer_pid=53631)==35017
for value in ('', 'not-a-handle', '0', '-1'):
 try:validate_owner_handle(value,consumer_pid=53631)
 except RuntimeError:pass
 else:raise AssertionError(value)
try:validate_owner_handle('53631',consumer_pid=53631)
except RuntimeError as error:assert 'unified exec session' in str(error)
else:raise AssertionError('consumer PID accepted as owner handle')
`;
  const result = spawnSync('python3', ['-c', script, path.dirname(helper)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

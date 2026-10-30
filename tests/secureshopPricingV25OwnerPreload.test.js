'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const ROOT = path.resolve(__dirname, '..');

if (process.env.V25_PRELOAD_CONTROL_CHILD === '1') {
  test('inherited Python grant precedes original no-argument output callers', async t => {
    const output = require('./fixtures/pricingOwnedOutput');
    const admitted = output.v25Admission();
    assert(output.isV25Admission(admitted));
    assert.equal(output.pricingOwnedOutputRoot(), process.env.OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT);
    assert.throws(() => require('./postgres/ownedPricingManualConsumer').run(),
      { code: 'V25_MANUAL_NOT_ADMITTED' });
    assert.deepEqual(require('./postgres/ownedPricingManualConsumer').contract().budget,
      require('./fixtures/secureshopPricingActual').actualPricingBudget(true, false, 'baseline').budget);
    require('./fixtures/secureshopPricingAssembled').writePricingActivationDiagnostic([{ controlled: true }]);
    assert(fs.existsSync(path.join(output.pricingOwnedOutputRoot(), 'pricing-activation-diagnostic.json')));
    const prior = global.fetch;
    const stop = Object.assign(Error('controlled before-store stop'), { code: 'CONTROLLED_STOP' });
    global.fetch = async url => {
      assert.equal(String(url), 'http://127.0.0.1:11434/api/tags');
      return new Response(JSON.stringify({ models: [{ name: 'llama3.1:8b',
        digest: '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e' }] }));
    };
    const dependencies = Object.fromEntries(['identity','im','agents','review','launches',
      'conversations','conversationRepository','turns','journal','coordinator','catalog',
      'products','authority','owner','auth','client'].map(key => [key, {}]));
    dependencies.im = { query: async () => { throw stop; }, connect: async () => { throw stop; } };
    try {
      await assert.rejects(() => require('./fixtures/secureshopPricingActual')(dependencies), error => error === stop);
    } finally { global.fetch = prior; }
    assert(fs.existsSync(path.join(output.pricingOwnedOutputRoot(), 'pricing-actual-result.json')));
    const consumer = require('./postgres/ownedPricingManualConsumer');
    const controlledDependencies = Object.fromEntries(Object.entries(dependencies)
      .filter(([key]) => key !== 'client'));
    t.mock.method(performance, 'now', () => admitted.deadline + 1);
    await assert.rejects(() => consumer._consume({ ...admitted, admitted,
      dependencies: controlledDependencies, signal: new AbortController().signal }),
    { code: 'V25_MANUAL_EXPIRED' });
    const descriptorBytes = fs.readFileSync(admitted.descriptorPath);
    fs.writeFileSync(admitted.descriptorPath, Buffer.concat([descriptorBytes, Buffer.from(' ')]));
    assert.throws(output.pricingOwnedOutputRoot);
    assert.throws(output.v25Admission);
    await assert.rejects(() => output.admitV25FromInheritedOwner(), /only once/);
  });
} else {
  const PYTHON = String.raw`
import hashlib,json,os,pathlib,shutil,subprocess,sys,uuid
root,node,test_file,workspace,mutation=sys.argv[1:]
base=pathlib.Path(root)/'tasks/qualification'
run=base/('pricing-private-'+uuid.uuid4().hex)
run.mkdir(mode=0o700)
try:
 os.chmod(run,0o700)
 cohort=run/'cohort';cohort.mkdir(mode=0o700)
 output=cohort/'output';output.mkdir(mode=0o700)
 owner='10000000-0000-4000-8000-000000000001';nonce='b'*12
 identity=dict(ownerId=owner,workspaceId=workspace,qualificationNonce=nonce,containerId='c'*64,
   imageId='sha256:'+'d'*64,packageSha256='e'*64,profile='owasp-ai-goat-owned-pricing-http-'+nonce,
   origin='http://127.0.0.1:18093')
 descriptor=dict(version=1,**identity,token='t'*43)
 raw=(json.dumps(descriptor,separators=(',',':'))+'\n').encode()
 descriptor_path=cohort/'private-executor.json'
 fd=os.open(descriptor_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as file:file.write(raw)
 ready_r,ready_w=os.pipe();grant_r,grant_w=os.pipe()
 env=os.environ.copy();env.pop('NODE_TEST_CONTEXT',None);env.update(dict(
   SECURESHOP_PRICING_V25_MANUAL_NATIVE='1',PERSONA_PRICING_NATIVE='1',PERSONA_PRICING_ACTUAL='1',
   PERSONA_PRICING_MANUAL_ONLY='1',PERSONA_PRICING_ACTUAL_REMAINING='0',PERSONA_PRICING_CANONICAL='1',
   PERSONA_PRICING_COHORT='baseline',PG_TEST_DISPOSABLE='yes',OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=root,
   OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT=str(output),SECURESHOP_PRICING_V25_READY_FD=str(ready_w),
   SECURESHOP_PRICING_V25_ADMISSION_FD=str(grant_r),V25_PRELOAD_CONTROL_CHILD='1'))
 child=subprocess.Popen([node,'--import',str(pathlib.Path(root)/'tests/fixtures/secureshopPricingV25OwnerPreload.mjs'),
   '--test','--test-isolation=none','--test-reporter=tap','--test-concurrency=1',test_file],cwd=root,env=env,
   pass_fds=(ready_w,grant_r),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 os.close(ready_w);os.close(grant_r)
 assert os.read(ready_r,1)==b'R';os.close(ready_r)
 stat=output.stat()
 grant=dict(version=1,target='original-v25-pricing-manual-owner-grant-v1',runId=run.name.removeprefix('pricing-private-'),
   ownerId=owner,launcherPid=os.getpid(),workerPid=child.pid,workspace=root,ownerPlanSha256='1'*64,
   snapshotSha256='2'*64,directory=str(cohort),descriptorPath=str(descriptor_path),
   descriptorSha256=hashlib.sha256(raw).hexdigest(),outputRoot=str(output),
   outputIdentity=dict(dev=stat.st_dev,ino=stat.st_ino,uid=stat.st_uid,mode=0o700),
   remainingMs=840000,executorIdentity=identity)
 if mutation=='foreign-worker':grant['workerPid']+=1
 elif mutation=='wrong-descriptor':grant['descriptorSha256']='0'*64
 elif mutation=='wrong-output':grant['outputIdentity']['ino']+=1
 elif mutation=='wrong-workspace':grant['workspace']=str(cohort)
 elif mutation=='expired':grant['remainingMs']=0
 elif mutation=='unknown-key':grant['extra']='forbidden'
 else:assert mutation=='valid'
 encoded=json.dumps(grant,separators=(',',':')).encode();assert len(encoded)<=4096
 os.write(grant_w,encoded);os.close(grant_w)
 stdout,stderr=child.communicate(timeout=20)
 if mutation=='valid':
  assert child.returncode==0,'preloaded controlled child failed'
  assert b'1..1' in stdout and b'# pass 1' in stdout
 else:
  assert child.returncode!=0,'invalid inherited grant was admitted'
  assert b'# pass 1' not in stdout
  assert not (output/'pricing-actual-result.json').exists()
finally:
 if 'child' in locals() and child.poll() is None:child.kill();child.communicate()
 for name in ('ready_r','ready_w','grant_r','grant_w'):
  if name in locals():
   try:os.close(locals()[name])
   except OSError:pass
 shutil.rmtree(run)
`;
  for (const mutation of ['valid','foreign-worker','wrong-descriptor','wrong-output',
    'wrong-workspace','expired','unknown-key']) test(`Python-to-preloaded-Node grant ${mutation}`, () => {
    const python = process.env.PYTHON || '/usr/bin/python3';
    const workspace = require('../scripts/application-data-root').workspaceId(ROOT);
    const run = spawnSync(python, ['-B', '-c', PYTHON, ROOT, process.execPath, __filename, workspace, mutation],
      { cwd: ROOT, encoding: 'utf8', timeout: 30000, maxBuffer: 8192 });
    assert.equal(run.status, 0, (run.stderr || '').slice(-1000));
    assert.equal(run.stdout, '');
  });
}

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { PassThrough } = require('node:stream');

const filename = path.join(__dirname, 'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js');
const source = fs.readFileSync(filename, 'utf8');
test('original V24 uses only its inherited paired renderer while legacy template admission remains distinct',async()=>{
  const begin=source.indexOf('async function capturePolicyInstructionRenderer(');
  const stop=source.indexOf('function assertPolicyInstructionRepositoryEvidencePath(',begin);
  const actualRequire=require('node:module').createRequire(filename);
  const capture=new vm.Script(source.slice(begin,stop)+'\ncapturePolicyInstructionRenderer')
    .runInNewContext({require:actualRequire,process:{env:{}}});
  await assert.rejects(capture(path.resolve(__dirname,'..'),{}));
  const selection=source.slice(source.indexOf('    externalPolicyRenderer = POLICY_INSTRUCTION_BROWSER'),
    source.indexOf("    if (POLICY_RENDERER_BROWSER) assert.ok(externalPolicyRenderer"));
  assert.match(selection,/POLICY_INSTRUCTION_BROWSER\s*\? await capturePolicyInstructionRenderer\(workspace\)\s*: POLICY_TEMPLATE_BROWSER\s*\? await require\('\.\.\/fixtures\/secureshopDisposablePolicyRenderer'\)/);
  assert.match(selection,/: POLICY_RENDERER_BROWSER\s*\? await capturePolicyRenderer/);
  assert.equal(createHash('sha256').update(fs.readFileSync(path.join(__dirname,'fixtures/secureshopPolicyInstructionRenderedScenario.js'))).digest('hex'),
    'e43cac8bb54961906d64933756dde9bbd741e90ba8385209864a9a6ebb0d674e');
});
const start = source.indexOf('function assertPolicyInstructionRepositoryEvidencePath(');
const end = source.indexOf('function assertUserLookupRepositoryEvidencePath(', start);
assert(start > 0 && end > start);
// Execute the actual checked-in helper definitions, not a second producer or
// a browser substitute claiming native evidence. Only filesystem/time are fake.
const program = new vm.Script(source.slice(start, end) +
  '\n({ admit:assertPolicyInstructionRepositoryEvidencePath, ack:acknowledgePolicyInstructionBrowser, args:policyInstructionBrowserArgs, detach:detachPolicyInstructionBootstrapLogs, selector:assertPolicyInstructionSandboxSelector });');

function fixture({ mutateAck = value => value, publish = true, late = false,
  ackMetadata = null, changeDuringRead = false, publicationFailure = null,
  ackTransition = null, partialMetadata = null, root = '/owned/repository', streams = {} } = {}) {
  const runId = 'a'.repeat(32);
  const directory = `${root}/tasks/qualification/system-original-owner-${runId}`;
  const temporary = `${directory}/runtime/tmp`, profile = `${temporary}/owasp-ai-goat-role-policy-instruction-abc123`;
  const executable = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const evidence = `${directory}/policy-instruction-browser.json`;
  const birthPath = `${directory}/browser-birth.json`, ackPath = `${directory}/browser-ack.json`;
  const files = new Map(), events = []; let clock = 0, inode = 1;
  const put = (name, data = null, mode = data === null ? 0o700 : 0o600) => {
    const row = { dev: 1, ino: inode++, size: data?.length || 0, mtimeMs: 1, ctimeMs: 1,
      uid: 501, mode, nlink: 1, data, symlink: false };
    row.isDirectory = () => row.data === null && !row.symlink;
    row.isFile = () => row.data !== null && !row.symlink;
    row.isSymbolicLink = () => row.symlink;
    files.set(name, row); return row;
  };
  [root, `${root}/tasks/qualification`, directory, `${directory}/runtime`, temporary, profile].forEach(p => put(p));
  put(executable, Buffer.from('not executed'));
  const get = name => { const row = files.get(name); if (!row) throw Object.assign(Error('missing'), { code: 'ENOENT' }); return row; };
  const sync = { constants: { O_RDONLY: 0, O_NOFOLLOW: 256, O_NONBLOCK: 4, O_DIRECTORY: 8 },
    lstatSync: get, realpathSync: name => { const row = get(name); return row.symlink ? '/different' : name; } };
  const unlink = async name => { const row = get(name); files.delete(name); row.nlink--; row.ctimeMs++; };
  const asyncFs = { lstat: async name => {
    if (name === `${ackPath}.partial` && ackTransition === 'during-partial-stat'
      && files.has(name)) await unlink(name);
    return { ...get(name) };
  }, realpath: async name => sync.realpathSync(name),
    link: async (from, to) => {
      events.push('link-final');
      assert(events.includes('birth-synced') && events.includes('birth-closed'));
      assert(!files.has(to), 'Final name cannot be visible during partial write');
      if (publicationFailure === 'existing-final') {
        put(to, Buffer.from('foreign-final'));
        throw Object.assign(Error('existing final'), { code: 'EEXIST' });
      }
      const row = get(from); row.nlink++; row.ctimeMs++; files.set(to, row);
    },
    unlink: async name => {
      if (publicationFailure === 'partial-unlink' && name === `${birthPath}.partial`)
        throw Error('partial unlink failed');
      events.push('unlink-partial'); await unlink(name);
    },
    open: async (name, flags, mode) => {
      let row;
      if (flags === 'wx') {
        assert(!files.has(name)); assert.equal(mode, 0o600); row = put(name, Buffer.alloc(0), mode);
      } else { assert.equal(flags, name === directory ? 264 : 260); row = get(name); if (row.symlink) throw Object.assign(Error('symlink'), { code: 'ELOOP' }); }
      return { stat: async () => ({ ...row }),
        writeFile: async data => {
          assert.equal(name, `${birthPath}.partial`); assert(!files.has(birthPath));
          row.data = Buffer.from(data); row.size = row.data.length; events.push('birth-written');
          if (publicationFailure === 'write') throw Error('write failed');
        },
        sync: async () => {
          if (name !== directory) {
            assert(!files.has(birthPath));
            if (publicationFailure === 'fsync') throw Error('fsync failed');
            events.push('birth-synced'); return;
          }
          events.push('directory-synced');
          if (publicationFailure === 'directory-fsync') throw Error('directory fsync failed');
          if (publish) {
            const record = get(birthPath).data, birth = JSON.parse(record);
            let ack = { version: 1, runId, birthSha256: createHash('sha256').update(record).digest('hex'),
              workerPid: 123, browserPid: 321, profilePath: profile, birth: [100, 9], pgid: 320 };
            ack = mutateAck(ack, birth);
            const ackRow = put(ackPath, Buffer.from(typeof ack === 'string' ? ack : JSON.stringify(ack) + '\n'));
            if (ackMetadata) Object.assign(ackRow, ackMetadata);
            if (ackTransition) { ackRow.nlink = 2; files.set(`${ackPath}.partial`, ackRow); }
            if (partialMetadata) files.set(`${ackPath}.partial`, { ...ackRow, ...partialMetadata });
          }
        },
        read: async buffer => { row.data.copy(buffer); if (late) clock += 15001;
          if (changeDuringRead) row.ctimeMs++;
          if (ackTransition === 'during-read' && files.has(`${ackPath}.partial`)) await unlink(`${ackPath}.partial`);
          return { bytesRead: Math.min(buffer.length, row.data.length) }; },
        close: async () => {
          events.push(name === `${birthPath}.partial` ? 'birth-closed' : name === directory ? 'directory-closed' : 'ack-closed');
          if (publicationFailure === 'close' && name === `${birthPath}.partial`) throw Error('close failed');
        },
      };
    } };
  const api = program.runInNewContext({ assert, path, fsSync: sync, fs: asyncFs, Buffer, createHash,
    process: { cwd: () => root, getuid: () => 501, pid: 123, ...streams },
    performance: { now: () => clock }, setTimeout: callback => {
      clock += 25;
      if (ackTransition === 'poll' && files.has(`${ackPath}.partial`)) void unlink(`${ackPath}.partial`);
      queueMicrotask(callback);
    } });
  const env = { SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE: '1', PG_TEST_DISPOSABLE: 'yes', NODE_ENV: 'test',
    SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX: '1',
    OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: root, SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID: runId,
    SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY: directory,
    SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_BROWSER_SHA256: 'b'.repeat(64),
    TMPDIR: temporary, TMP: temporary, TEMP: temporary, MAC_CHROMIUM_TMPDIR: temporary, PUPPETEER_EXECUTABLE_PATH: executable };
  return { api, env, root, evidence, directory, temporary, profile, files, put, events, birthPath, ackPath,
    browser: { process: () => ({ pid: 321 }) }, now: () => clock };
}

test('V24 admits only exact private repository owner paths and fresh artifacts', () => {
  const f = fixture();
  const admitted = f.api.admit(f.root, f.evidence, f.env);
  assert.equal(admitted.temporary, f.temporary); assert(Object.isFrozen(admitted));
  for (const [key, value] of [
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE', '0'], ['PG_TEST_DISPOSABLE', 'no'],
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_RUN_ID', 'A'.repeat(32)],
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_DIRECTORY', `${f.directory}/..`],
    ['TMPDIR', '/tmp'], ['PUPPETEER_EXECUTABLE_PATH', '/different/browser'],
    ['MAC_CHROMIUM_TMPDIR', '/tmp'], ['MAC_CHROMIUM_TMPDIR', undefined],
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX', undefined],
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX', '0'],
    ['SECURESHOP_POLICY_INSTRUCTION_BROWSER_OWNER_BROWSER_SHA256', 'missing'],
  ]) assert.throws(() => f.api.admit(f.root, f.evidence, { ...f.env, [key]: value }), key);
  assert.throws(() => f.api.admit(f.root, '/tmp/policy-instruction-browser.json', f.env));
  for (const target of [f.evidence, f.birthPath, `${f.birthPath}.partial`, f.ackPath, `${f.ackPath}.partial`]) {
    f.put(target, Buffer.from('{}')); assert.throws(() => f.api.admit(f.root, f.evidence, f.env)); f.files.delete(target);
  }
  for (const patch of [{ mode: 0o755 }, { uid: 502 }, { symlink: true }]) {
    const row = f.files.get(f.directory), saved = { ...row };
    Object.assign(row, patch); assert.throws(() => f.api.admit(f.root, f.evidence, f.env)); Object.assign(row, saved);
  }
});

test('actual helper publishes durable intent and accepts only joined canonical owner ACK', async () => {
  const f = fixture(); const admission = f.api.admit(f.root, f.evidence, f.env);
  await f.api.ack(admission, f.browser, f.profile);
  assert.deepEqual(f.events, ['birth-written', 'birth-synced', 'birth-closed', 'link-final',
    'unlink-partial', 'directory-synced', 'directory-closed', 'ack-closed']);
  assert.deepEqual(JSON.parse(f.files.get(f.birthPath).data), { version: 1, runId: 'a'.repeat(32),
    workerPid: 123, browserPid: 321, profilePath: f.profile });
  assert(f.files.has(f.profile), 'Only the independently inspecting owner may delete this profile');
});

test('forged, malformed, stale and secret-bearing ACKs never admit browser work', async () => {
  const mutations = [a => ({ ...a, version: true }), a => ({ ...a, runId: 'c'.repeat(32) }),
    a => ({ ...a, birthSha256: '0'.repeat(64) }), a => ({ ...a, workerPid: 124 }),
    a => ({ ...a, browserPid: 322 }), a => ({ ...a, profilePath: '/tmp/other' }),
    a => ({ ...a, birth: [0, 1] }), a => ({ ...a, birth: [100, 1000000] }),
    a => ({ ...a, birth: [100, true] }), a => ({ ...a, pgid: true }),
    a => ({ ...a, token: 'must-not-be-accepted' }),
    a => JSON.stringify(a).replace('"version":1', '"version":0,"version":1') + '\n',
    a => JSON.stringify(a) + '\n\n'];
  for (const mutateAck of mutations) {
    const f = fixture({ mutateAck }); const admission = f.api.admit(f.root, f.evidence, f.env);
    await assert.rejects(f.api.ack(admission, f.browser, f.profile));
    assert(f.events.includes('ack-closed')); assert(f.files.has(f.profile));
  }
  const late = fixture({ late: true });
  await assert.rejects(late.api.ack(late.api.admit(late.root, late.evidence, late.env), late.browser, late.profile), /deadline/);
});

test('birth publication is absent until durable close and never replaces an existing final record', async () => {
  for (const publicationFailure of ['write', 'fsync', 'close', 'existing-final']) {
    const f = fixture({ publicationFailure });
    await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile));
    assert(f.events.includes('birth-closed'));
    assert(!f.files.has(`${f.birthPath}.partial`));
    if (publicationFailure === 'existing-final')
      assert.equal(f.files.get(f.birthPath).data.toString(), 'foreign-final');
    else assert(!f.files.has(f.birthPath));
    assert(!f.files.has(f.ackPath)); assert(f.files.has(f.profile));
  }
});

test('publication cleanup and durability failures retain evidence and never await or accept ACK', async () => {
  for (const publicationFailure of ['partial-unlink', 'directory-fsync']) {
    const f = fixture({ publicationFailure });
    await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile),
      publicationFailure === 'partial-unlink' ? /publication and cleanup failed/ : /directory fsync failed/);
    assert(f.files.has(f.birthPath)); assert(f.files.has(f.profile));
    assert(!f.files.has(f.ackPath)); assert.equal(f.now(), 0);
    if (publicationFailure === 'partial-unlink') {
      assert.equal(f.files.get(f.birthPath).nlink, 2);
      assert.equal(f.files.get(`${f.birthPath}.partial`), f.files.get(f.birthPath));
    } else {
      assert(!f.files.has(`${f.birthPath}.partial`));
      assert(f.events.includes('directory-closed'));
    }
  }
});

test('exact ACK publication transition is re-polled, never admitted from a mixed or two-link snapshot', async () => {
  for (const ackTransition of ['poll', 'during-read', 'during-partial-stat']) {
    const f = fixture({ ackTransition });
    await f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile);
    assert.equal(f.now(), 25);
    assert.equal(f.events.filter(value => value === 'ack-closed').length, 2);
    assert.equal(f.files.get(f.ackPath).nlink, 1);
    assert(!f.files.has(`${f.ackPath}.partial`));
  }
  const pending = fixture({ ackTransition: 'never-settles' });
  await assert.rejects(pending.api.ack(pending.api.admit(pending.root, pending.evidence, pending.env),
    pending.browser, pending.profile), /ACK unavailable/);
  assert.equal(pending.now(), 15000);
});

test('known transition does not excuse malformed bytes or unknown partial identities', async () => {
  for (const options of [
    { ackTransition: 'poll', mutateAck: () => '{}' },
    { ackTransition: 'poll', mutateAck: a => ({ ...a, token: 'not allowed' }) },
    ...[{ ino: 999 }, { mode: 0o644 }, { uid: 502 }, { nlink: 1 }, { size: 1 }, { ctimeMs: 99 }]
      .map(partialMetadata => ({ ackTransition: 'poll', partialMetadata })),
    { partialMetadata: {} }, // Stable one-link final must not coexist with any partial.
  ]) {
    const f = fixture(options);
    await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile));
    assert.equal(f.now(), 0); assert(f.files.has(f.profile));
    assert(f.events.includes('ack-closed'));
  }
});

test('missing owner ACK is bounded and leaves actual cleanup obligation intact', async () => {
  const f = fixture({ publish: false });
  await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile), /ACK unavailable/);
  assert.equal(f.now(), 15000); assert(f.files.has(f.birthPath)); assert(f.files.has(f.profile));
});

test('ACK file identity/privacy/size and read stability are enforced without unbounded reads', async () => {
  for (const ackMetadata of [{ mode: 0o644 }, { uid: 502 }, { nlink: 2 }, { symlink: true },
    { size: 4097 }, { isFile: () => false }]) {
    const f = fixture({ ackMetadata });
    await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile));
    assert(f.files.has(f.profile));
    if (!ackMetadata.symlink) assert(f.events.includes('ack-closed'));
  }
  const f = fixture({ changeDuringRead: true });
  await assert.rejects(f.api.ack(f.api.admit(f.root, f.evidence, f.env), f.browser, f.profile));
  assert(f.events.includes('ack-closed'));
});

test('foreign profile, bad browser PID and preexisting birth record cannot publish fresh intent', async () => {
  for (const variant of ['profile', 'pid', 'birth']) {
    const f = fixture(), admission = f.api.admit(f.root, f.evidence, f.env);
    if (variant === 'birth') f.put(`${f.birthPath}.partial`, Buffer.from('prior intent'));
    await assert.rejects(f.api.ack(admission,
      variant === 'pid' ? { process: () => ({ pid: true }) } : f.browser,
      variant === 'profile' ? '/tmp/unowned' : f.profile));
    assert(!f.events.includes('birth-written'));
  }
});

test('V24-only wiring blocks first page on ACK and leaves other cohorts and original lesson intact', () => {
  const admission = source.indexOf('const policyInstructionBrowserAdmission = POLICY_INSTRUCTION_BROWSER');
  const launch = source.indexOf("browser = await require('puppeteer').launch", admission);
  const ack = source.indexOf('await acknowledgePolicyInstructionBrowser(policyInstructionBrowserAdmission, browser, profile)', launch);
  const page = source.indexOf('const page = adminConfirmationBoundary', launch);
  assert(admission > 0 && launch > admission && ack > launch && page > ack);
  assert(source.includes('profile && !policyInstructionBrowserAdmission && !mailActionsAdmission && !q05BrowserAdmission && !adminConfirmationAdmission && !adminResetAdmission && fs.rm(profile'));
  assert(source.includes('else if (USER_LOOKUP_BROWSER) assertUserLookupRepositoryEvidencePath(workspace, evidencePath);'));
  assert(source.includes('assert.ok(!path.resolve(evidencePath).startsWith(`${workspace}${path.sep}`));'));
  assert(source.includes('((policyInstructionBrowserAdmission || Q05_REVIEW_BROWSER || USER_LOOKUP_BROWSER || mailActionsAdmission || adminConfirmationAdmission || adminResetAdmission) ? { args: browserArgs } : {})'));
  const scenario = fs.readFileSync(path.join(__dirname, 'fixtures/secureshopPolicyInstructionRenderedScenario.js'));
  assert.equal(createHash('sha256').update(scenario).digest('hex'), 'e43cac8bb54961906d64933756dde9bbd741e90ba8385209864a9a6ebb0d674e');
});

const launchStart = source.indexOf('    const userLookupBrowserAdmission = USER_LOOKUP_BROWSER');
const launchEnd = source.indexOf('    await page.setViewport(', launchStart);
assert(launchStart > 0 && launchEnd > launchStart);
const launchProgram = new vm.Script('(async()=>{'+source.slice(launchStart,launchEnd)+'\nreturn page;})()');
function actualOwnerEnvironment(policyVersion='configuration-readability-relative-v3') {
  const I = require('./postgres/ownedSystemOriginalBrowserOwner')._internals;
  return I.childEnvironment({root:I.ROOT,runId:'a'.repeat(32),node:I.NODE,
    producer:{root:I.ROOT,runId:'a'.repeat(32)},signal:new AbortController().signal,
    nodeSha256:'c'.repeat(64),pythonSha256:'d'.repeat(64),
    browser:I.BROWSER,browserSha256:'b'.repeat(64),pgNonce:'b'.repeat(12),pgPort:15432,policyVersion},
  {system:{client:{},port:18090,baseURL:'http://127.0.0.1:18090',token:'t'.repeat(43)},
    policy:{client:{},port:18091,baseURL:'http://127.0.0.1:18091'},signal:new AbortController().signal,deadline:performance.now()+900000});
}
async function composedLaunch({ mode='v24', policyVersion='configuration-readability-relative-v3',
  failure=null, mutateEnv=()=>{}, mutateProfile=()=>{} }={}) {
  const env={...actualOwnerEnvironment(policyVersion)};
  if(mode!=='v24') {delete env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_NATIVE;delete env.SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX;}
  mutateEnv(env);
  const streams={stdout:new PassThrough(),stderr:new PassThrough()}, captured={stdout:'',stderr:''};
  for(const name of Object.keys(streams)) streams[name].on('data',b=>captured[name]+=b.toString());
  const f=fixture({root:env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE,streams,publish:failure!=='ack'});
  f.api.selector(env,mode==='v24');
  const events=[], child={pid:321,stdout:new PassThrough(),stderr:new PassThrough()};
  const page={},browser={process:()=>child,newPage:async()=>{events.push('page');return page;}};
  let launchOptions, launches=0;
  const admission=mode==='v24'?f.api.admit(f.root,f.evidence,env):null;
  mutateProfile(f);
  const knownArgs=['existing-'+mode];
  const context={process:{env},workspace:f.root,evidencePath:f.evidence,profile:f.profile,
    origin:'http://127.0.0.1:12345',executablePath:env.PUPPETEER_EXECUTABLE_PATH,
    USER_LOOKUP_BROWSER:mode==='lookup',Q05_REVIEW_BROWSER:mode==='q05',
    policyInstructionBrowserAdmission:admission,
    policyInstructionBrowserArgs:f.api.args,detachPolicyInstructionBootstrapLogs:f.api.detach,
    acknowledgePolicyInstructionBrowser:async(...args)=>{events.push('ack');await f.api.ack(...args);},
    q05BrowserAdmission:mode==='q05'?{browserArgs:()=>knownArgs}:null,
    q05Reviews:{acknowledgeOrClose:async()=>events.push('q05-ack')},
    adminConfirmationAdmission:null,adminResetAdmission:null,
    mailActionsAdmission:mode==='mail'?{browserArgs:()=>knownArgs,watchBrowserTargets:()=>null,
      acknowledgeBrowser:async()=>events.push('mail-ack')}:null,
    require:name=>name==='puppeteer'?{launch:async opts=>{
      launches++;launchOptions=opts;events.push('launch');
      if(opts.dumpio) for(const name of ['stdout','stderr']) child[name].pipe(streams[name]);
      child.stdout.write('bootstrap out\n');child.stderr.write('raw bootstrap failure detail\n');
      if(failure==='launch') throw Error('original launch failure');
      if(failure==='detach') child.stdout.unpipe=()=>{throw Error('unpipe failure');};
      return browser;
    }}:{userLookupBrowserArgs:()=>knownArgs},
  };
  try {
    const result=await launchProgram.runInNewContext(context);
    child.stdout.write('post-start private work');child.stderr.write('post-start private error');
    return {result,page,events,launchOptions,captured,launches};
  } catch(error) {
    error.control={events,launchOptions,captured,launches,stderrDetached:child.stderr.listenerCount('data')===0};throw error;
  } finally {
    // Undo only the injected method fault before retiring controlled streams.
    delete child.stdout.unpipe;
    child.stdout.unpipe();child.stderr.unpipe();
    for(const stream of [...Object.values(streams),child.stdout,child.stderr])stream.destroy();
  }
}
test('actual owner env → repository admission → launch detaches bootstrap pipes before actual ACK and first page',async()=>{
  for(const policyVersion of ['configuration-readability-relative-v3','configuration-readability-token-contrast-v4']) {
    const r=await composedLaunch({policyVersion});assert.equal(r.result,r.page);
    assert.deepEqual(r.events,['launch','ack','page']);assert.equal(r.launchOptions.dumpio,true);
    assert(r.launchOptions.args.includes('--no-sandbox'));assert(r.launchOptions.args.includes('--disable-background-networking'));
    assert.deepEqual(r.captured,{stdout:'bootstrap out\n',stderr:'raw bootstrap failure detail\n'});
  }
  assert.throws(()=>actualOwnerEnvironment('configuration-readability-token-contrast-v5'));
});
test('actual launch keeps default and other cohort options separate; V24 opt-in cannot select another cohort',async()=>{
  for(const mode of ['default','q05','mail','lookup']) {
    const r=await composedLaunch({mode});assert.equal(r.launchOptions.dumpio,undefined);
    assert.deepEqual(r.launchOptions.args,mode==='default'?undefined:['existing-'+mode]);
    assert.deepEqual(r.captured,{stdout:'',stderr:''});
  }
  const f=fixture();f.api.selector({},false);
  for(const selected of [false,undefined]) assert.throws(()=>f.api.selector(f.env,selected));
  assert.throws(()=>f.api.selector({...f.env,SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX:'0'},true));
  const admission=f.api.admit(f.root,f.evidence,f.env);
  for(const origin of ['https://127.0.0.1:12345','http://localhost:12345','http://127.0.0.1:65536','http://127.0.0.1:12345/path'])
    assert.throws(()=>f.api.args(admission,f.profile,origin));
  assert.throws(()=>f.api.args(admission,'/tmp/foreign-profile','http://127.0.0.1:12345'));
  assert(source.includes('assertPolicyInstructionSandboxSelector(process.env, POLICY_INSTRUCTION_BROWSER);'));
});
test('failed bootstrap retains raw stderr; ACK/detach failure never permits page work',async()=>{
  for(const failure of ['launch','ack','detach']) await assert.rejects(composedLaunch({failure}),error=>{
    assert.equal(error.control.launches,1);assert(!error.control.events.includes('page'));
    assert.equal(error.control.captured.stderr,'raw bootstrap failure detail\n');
    if(failure!=='launch')assert.equal(error.control.stderrDetached,true);
    if(failure==='launch')assert.equal(error.message,'original launch failure');
    return true;
  });
  for(const key of ['MAC_CHROMIUM_TMPDIR','SECURESHOP_POLICY_INSTRUCTION_BROWSER_TEST_NO_SANDBOX'])
    await assert.rejects(composedLaunch({mutateEnv:env=>delete env[key]}));
  await assert.rejects(composedLaunch({mutateProfile:f=>{f.files.get(f.profile).mode=0o755;}}));
});

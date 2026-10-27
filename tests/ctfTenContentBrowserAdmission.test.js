'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const admission=require('./fixtures/ctfTenContentBrowserAdmission');
const ROOT=path.resolve(__dirname,'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');

test('learner browser has a distinct private profile, birth kind and selector',async t=>{
  const parent=path.join(ROOT,'tasks/qualification');
  const run=fs.mkdtempSync(path.join(parent,'dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','l-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_LEARNER_ENTRY_HINT_BROWSER_NATIVE:'1',
    CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED:'1',PG_TEST_DISPOSABLE:'yes',
    CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_LEARNER_ENTRY_HINT_BROWSER_TMP:short,
    CTF_LEARNER_ENTRY_HINT_BROWSER_RECORD:path.join(evidence,'learner-entry-hint-browser-birth.json'),
    CTF_LEARNER_ENTRY_HINT_BROWSER_ACK:path.join(evidence,'learner-entry-hint-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'learner').profile,
    path.join(evidence,'learner-entry-hint-profile'));
  assert.equal(admission.browserEnvironment(env,'learner').MAC_CHROMIUM_TMPDIR,short);
  assert.throws(()=>admission.admit({...env,CTF_CONFIG_RENDERED_ISOLATED:'1'},evidence,'learner'));
  assert.throws(()=>admission.admit({...env,CTF_PREVIEW_RENDERED_ISOLATED:'1'},evidence,'learner'));
  assert.throws(()=>admission.admit({...env,CTF_LEARNER_ENTRY_HINT_BROWSER_NATIVE:'0'},evidence,'learner'));
  const pid=process.pid+100005;
  const profile=path.join(evidence,'learner-entry-hint-profile');
  const capture=args=>({schemaVersion:2,processes:[{kind:args.kind,pid,parentPid:process.pid,
    pgid:process.pid,sessionId:process.pid,uid:process.getuid(),birth:[123,456],
    executablePath:executable,executableSha256:env.ANALYTICS_BROWSER_SHA256}]});
  const pending=admission.acknowledge(env,{profile,pid,capture});
  const recordPath=env.CTF_LEARNER_ENTRY_HINT_BROWSER_RECORD;
  const until=Date.now()+2000;
  while(!fs.existsSync(recordPath)&&Date.now()<until)await new Promise(resolve=>setTimeout(resolve,10));
  assert.equal(JSON.parse(fs.readFileSync(recordPath)).processes[0].kind,
    'ctf_learner_entry_hint_browser');
  fs.writeFileSync(env.CTF_LEARNER_ENTRY_HINT_BROWSER_ACK,JSON.stringify({schemaVersion:1,
    recordSha256:sha(fs.readFileSync(recordPath)),parentPid:process.pid,browserPid:pid,profile}),
  {flag:'wx',mode:0o600});
  assert.equal((await pending).pid,pid);
});

test('CTF browser adapter admits only a private exact current-host scope',t=>{
  const parent=path.join(ROOT,'tasks/qualification');
  const run=fs.mkdtempSync(path.join(parent,'dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','c-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_TEN_CONTENT_BROWSER_NATIVE:'1',CTF_TEN_CONTENT_ISOLATED:'1',
    PG_TEST_DISPOSABLE:'yes',CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_CONTENT_BROWSER_TMP:short,
    CTF_CONTENT_BROWSER_RECORD:path.join(evidence,'content-browser-birth.json'),
    CTF_CONTENT_BROWSER_ACK:path.join(evidence,'content-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'content').profile,path.join(evidence,'content-profile'));
  const chromeEnv=admission.browserEnvironment(env);
  assert.deepEqual(Object.keys(chromeEnv).sort(),['PATH','TMPDIR','TMP','TEMP',
    'MAC_CHROMIUM_TMPDIR','XDG_CACHE_HOME','XDG_CONFIG_HOME'].sort());
  assert.equal(chromeEnv.PATH,'/usr/bin:/bin');
  assert.equal(chromeEnv.MAC_CHROMIUM_TMPDIR,short);
  assert(admission.FLAGS.includes('--no-sandbox'));
  assert(admission.FLAGS.some(flag=>flag.startsWith('--proxy-server=')));
  assert.throws(()=>admission.admit({...env,CTF_CONTENT_BROWSER_TMP:'/tmp/foreign'},evidence,'content'));
  assert.throws(()=>admission.admit({...env,CTF_TEN_CONTENT_BROWSER_NATIVE:'0'},evidence,'content'));
  assert.throws(()=>admission.admit(env,evidence,'browser'));
});

test('CTF page admission waits for exact independent birth ACK',async t=>{
  const root=fs.mkdtempSync(path.join(ROOT,'tasks/tmp/ctf-birth-control-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_CONTENT_BROWSER_RECORD:path.join(root,'birth.json'),
    CTF_CONTENT_BROWSER_ACK:path.join(root,'ack.json'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  const pid=process.pid+100000,profile=path.join(root,'content-profile');
  const record={schemaVersion:2,processes:[{kind:'ctf_ten_content_browser',
    pid,parentPid:process.pid,pgid:process.pid,sessionId:process.pid,uid:process.getuid(),
    birth:[123,456],executablePath:executable,executableSha256:env.ANALYTICS_BROWSER_SHA256}]};
  const capture=()=>record;
  const acknowledged=admission.acknowledge(env,{profile,pid,capture});
  const until=Date.now()+2000;
  while(!fs.existsSync(env.CTF_CONTENT_BROWSER_RECORD)&&Date.now()<until)
    await new Promise(resolve=>setTimeout(resolve,10));
  assert(fs.existsSync(env.CTF_CONTENT_BROWSER_RECORD));
  const recordSha256=sha(fs.readFileSync(env.CTF_CONTENT_BROWSER_RECORD));
  fs.writeFileSync(env.CTF_CONTENT_BROWSER_ACK,JSON.stringify({schemaVersion:1,
    recordSha256,parentPid:process.pid,browserPid:pid,profile}),{flag:'wx',mode:0o600});
  assert.equal((await acknowledged).pid,pid);
  fs.unlinkSync(env.CTF_CONTENT_BROWSER_ACK);
  fs.unlinkSync(env.CTF_CONTENT_BROWSER_RECORD);
  fs.writeFileSync(env.CTF_CONTENT_BROWSER_ACK,JSON.stringify({schemaVersion:1,
    recordSha256:'0'.repeat(64),parentPid:process.pid,browserPid:pid,profile}),
    {flag:'wx',mode:0o600});
  await assert.rejects(admission.acknowledge(env,{profile,pid,capture}));
});

test('CTF Config browser admission is separate and rejects ten-content credentials',t=>{
  const parent=path.join(ROOT,'tasks/qualification');
  const run=fs.mkdtempSync(path.join(parent,'dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','g-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_CONFIG_BROWSER_NATIVE:'1',CTF_CONFIG_RENDERED_ISOLATED:'1',
    PG_TEST_DISPOSABLE:'yes',CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_CONFIG_BROWSER_TMP:short,
    CTF_CONFIG_BROWSER_RECORD:path.join(evidence,'config-browser-birth.json'),
    CTF_CONFIG_BROWSER_ACK:path.join(evidence,'config-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'config').profile,path.join(evidence,'config-profile'));
  assert.equal(admission.browserEnvironment(env,'config').MAC_CHROMIUM_TMPDIR,short);
  assert.throws(()=>admission.admit(env,evidence,'content'));
  assert.throws(()=>admission.admit({...env,CTF_CONFIG_BROWSER_NATIVE:'0'},evidence,'config'));
  assert.throws(()=>admission.admit({...env,CTF_TEN_CONTENT_ISOLATED:'1'},evidence,'config'));
  assert.throws(()=>admission.admit({...env,CTF_CONFIG_BROWSER_RECORD:path.join(evidence,'content-browser-birth.json')},evidence,'config'));
  assert.throws(()=>admission.admit({...env,CTF_CONFIG_BROWSER_TMP:'/tmp/foreign'},evidence,'config'));
});

test('CTF Config birth ACK is bound to its own kind, record, and profile',async t=>{
  const root=fs.mkdtempSync(path.join(ROOT,'tasks/tmp/ctf-config-birth-control-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const profile=path.join(root,'config-profile'),pid=process.pid+100001;
  const env={CTF_CONFIG_BROWSER_RECORD:path.join(root,'config-browser-birth.json'),
    CTF_CONFIG_BROWSER_ACK:path.join(root,'config-browser-ack.json'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  const capture=args=>({schemaVersion:2,processes:[{kind:args.kind,
    pid,parentPid:process.pid,pgid:process.pid,sessionId:process.pid,uid:process.getuid(),
    birth:[123,456],executablePath:executable,executableSha256:env.ANALYTICS_BROWSER_SHA256}]});
  const acknowledged=admission.acknowledge(env,{profile,pid,capture});
  const until=Date.now()+2000;
  while(!fs.existsSync(env.CTF_CONFIG_BROWSER_RECORD)&&Date.now()<until)
    await new Promise(resolve=>setTimeout(resolve,10));
  const record=JSON.parse(fs.readFileSync(env.CTF_CONFIG_BROWSER_RECORD));
  assert.equal(record.processes[0].kind,'ctf_config_browser');
  assert.equal(fs.existsSync(path.join(root,'content-browser-birth.json')),false);
  fs.writeFileSync(env.CTF_CONFIG_BROWSER_ACK,JSON.stringify({schemaVersion:1,
    recordSha256:sha(fs.readFileSync(env.CTF_CONFIG_BROWSER_RECORD)),
    parentPid:process.pid,browserPid:pid,profile}),{flag:'wx',mode:0o600});
  assert.equal((await acknowledged).pid,pid);
});

test('CTF Preview browser admission is disjoint from Config and content',t=>{
  const parent=path.join(ROOT,'tasks/qualification');
  const run=fs.mkdtempSync(path.join(parent,'dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','p-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_PREVIEW_BROWSER_NATIVE:'1',CTF_PREVIEW_RENDERED_ISOLATED:'1',
    PG_TEST_DISPOSABLE:'yes',CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_PREVIEW_BROWSER_TMP:short,
    CTF_PREVIEW_BROWSER_RECORD:path.join(evidence,'preview-browser-birth.json'),
    CTF_PREVIEW_BROWSER_ACK:path.join(evidence,'preview-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'preview').profile,path.join(evidence,'preview-profile'));
  assert.equal(admission.browserEnvironment(env,'preview').MAC_CHROMIUM_TMPDIR,short);
  assert.throws(()=>admission.admit(env,evidence,'config'));
  assert.throws(()=>admission.admit(env,evidence,'content'));
  assert.throws(()=>admission.admit({...env,CTF_PREVIEW_BROWSER_NATIVE:'0'},evidence,'preview'));
  assert.throws(()=>admission.admit({...env,CTF_CONFIG_RENDERED_ISOLATED:'1'},evidence,'preview'));
  assert.throws(()=>admission.admit({...env,CTF_PREVIEW_BROWSER_RECORD:path.join(evidence,'config-browser-birth.json')},evidence,'preview'));
  assert.throws(()=>admission.admit({...env,CTF_PREVIEW_BROWSER_TMP:'/tmp/foreign'},evidence,'preview'));
});

test('CTF Preview birth ACK uses a distinct kind and exact private record',async t=>{
  const root=fs.mkdtempSync(path.join(ROOT,'tasks/tmp/ctf-preview-birth-control-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const profile=path.join(root,'preview-profile'),pid=process.pid+100002;
  const env={CTF_PREVIEW_BROWSER_RECORD:path.join(root,'preview-browser-birth.json'),
    CTF_PREVIEW_BROWSER_ACK:path.join(root,'preview-browser-ack.json'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  const capture=args=>({schemaVersion:2,processes:[{kind:args.kind,
    pid,parentPid:process.pid,pgid:process.pid,sessionId:process.pid,uid:process.getuid(),
    birth:[123,456],executablePath:executable,executableSha256:env.ANALYTICS_BROWSER_SHA256}]});
  const acknowledged=admission.acknowledge(env,{profile,pid,capture});
  const until=Date.now()+2000;
  while(!fs.existsSync(env.CTF_PREVIEW_BROWSER_RECORD)&&Date.now()<until)
    await new Promise(resolve=>setTimeout(resolve,10));
  const record=JSON.parse(fs.readFileSync(env.CTF_PREVIEW_BROWSER_RECORD));
  assert.equal(record.processes[0].kind,'ctf_preview_browser');
  assert.equal(fs.existsSync(path.join(root,'config-browser-birth.json')),false);
  fs.writeFileSync(env.CTF_PREVIEW_BROWSER_ACK,JSON.stringify({schemaVersion:1,
    recordSha256:sha(fs.readFileSync(env.CTF_PREVIEW_BROWSER_RECORD)),
    parentPid:process.pid,browserPid:pid,profile}),{flag:'wx',mode:0o600});
  assert.equal((await acknowledged).pid,pid);
});

test('scored learner browser admission is disjoint and pins its owned profile',t=>{
  const parent=path.join(ROOT,'tasks/qualification');
  const run=fs.mkdtempSync(path.join(parent,'dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','a-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_LEARNER_ATTEMPT_GATE_BROWSER_NATIVE:'1',
    CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED:'1',PG_TEST_DISPOSABLE:'yes',
    CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_LEARNER_ATTEMPT_GATE_BROWSER_TMP:short,
    CTF_LEARNER_ATTEMPT_GATE_BROWSER_RECORD:path.join(evidence,'learner-attempt-gate-browser-birth.json'),
    CTF_LEARNER_ATTEMPT_GATE_BROWSER_ACK:path.join(evidence,'learner-attempt-gate-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'attemptGate').profile,
    path.join(evidence,'learner-attempt-gate-profile'));
  assert.equal(admission.browserEnvironment(env,'attemptGate').MAC_CHROMIUM_TMPDIR,short);
  assert.throws(()=>admission.admit(env,evidence,'learner'));
  assert.throws(()=>admission.admit({...env,CTF_LEARNER_ENTRY_HINT_RENDERED_ISOLATED:'1'},evidence,'attemptGate'));
  assert.throws(()=>admission.admit({...env,CTF_LEARNER_ATTEMPT_GATE_BROWSER_TMP:'/tmp/foreign'},evidence,'attemptGate'));
});

test('Fixed-practice browser admission has a disjoint exact birth and private profile',t=>{
  const run=fs.mkdtempSync(path.join(ROOT,'tasks/qualification/dvaia-ctf-stages-route-control-'));
  const short=path.join(ROOT,'tasks/tmp','f-'+createHash('sha256').update(run).digest('hex').slice(0,8));
  t.after(()=>{fs.rmSync(short,{recursive:true,force:true});fs.rmSync(run,{recursive:true,force:true});});
  fs.chmodSync(run,0o700);
  for(const directory of ['runtime','rendered-evidence','runtime/tmp','runtime/cache','runtime/config'])
    fs.mkdirSync(path.join(run,directory),{recursive:true,mode:0o700});
  fs.mkdirSync(short,{mode:0o700});
  const evidence=path.join(run,'rendered-evidence'),runtime=path.join(run,'runtime');
  const executable=path.join(ROOT,'tasks/runtime/node/node_modules/node/bin/node');
  const env={CTF_FIXED_PRACTICE_BROWSER_NATIVE:'1',CTF_FIXED_PRACTICE_RENDERED_ISOLATED:'1',
    PG_TEST_DISPOSABLE:'yes',CTF_CONTENT_SOURCE_ROOT:ROOT,CTF_RENDERED_EVIDENCE:evidence,
    CTF_CONTENT_RUNTIME_DIRECTORY:runtime,TMPDIR:path.join(runtime,'tmp'),
    XDG_CACHE_HOME:path.join(runtime,'cache'),XDG_CONFIG_HOME:path.join(runtime,'config'),
    CTF_FIXED_PRACTICE_BROWSER_TMP:short,
    CTF_FIXED_PRACTICE_BROWSER_RECORD:path.join(evidence,'fixed-practice-browser-birth.json'),
    CTF_FIXED_PRACTICE_BROWSER_ACK:path.join(evidence,'fixed-practice-browser-ack.json'),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:path.join(ROOT,'tests/postgres/secureshop_darwin_browser_birth.py'),
    ANALYTICS_BROWSER_EXECUTABLE:executable,PUPPETEER_EXECUTABLE_PATH:executable,
    ANALYTICS_BROWSER_SHA256:sha(fs.readFileSync(executable))};
  assert.equal(admission.admit(env,evidence,'fixedPractice').profile,
    path.join(evidence,'fixed-practice-profile'));
  assert.equal(admission.browserEnvironment(env,'fixedPractice').MAC_CHROMIUM_TMPDIR,short);
  assert.throws(()=>admission.admit(env,evidence,'attemptGate'));
  assert.throws(()=>admission.admit({...env,CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED:'1'},evidence,'fixedPractice'));
  assert.throws(()=>admission.admit({...env,CTF_FIXED_PRACTICE_BROWSER_RECORD:path.join(evidence,'preview-browser-birth.json')},evidence,'fixedPractice'));
  assert.throws(()=>admission.admit({...env,CTF_FIXED_PRACTICE_BROWSER_TMP:'/tmp/foreign'},evidence,'fixedPractice'));
});

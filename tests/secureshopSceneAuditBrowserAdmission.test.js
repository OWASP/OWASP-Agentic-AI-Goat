'use strict';
// Controlled V15 browser admission only; no browser, database or model starts.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {sceneAuditBrowserArgs}=require('./fixtures/secureshopSceneAuditBrowserAdmission');

const root=path.resolve(__dirname,'..');
const integration=path.join(__dirname,'postgres/secureshopAdminAuditJobsRendered.integration.test.js');
function fixture(t){
 const run=fs.mkdtempSync(path.join(root,'tasks/qualification/run-v15-admission-'));
 t.after(()=>fs.rmSync(run,{recursive:true,force:true}));
 const runtime=path.join(run,'runtime'),tmp=path.join(runtime,'tmp');
 fs.mkdirSync(tmp,{recursive:true,mode:0o700});
 const profile=fs.mkdtempSync(path.join(tmp,'dvaia-scene-audit-v15-'));
 const evidencePath=path.join(run,'scene-audit-v15-browser.json');
 const env={SECURESHOP_SCENE_AUDIT_TEST_NO_SANDBOX:'1',SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE:'1',
  PG_TEST_DISPOSABLE:'yes',LIVE_OLLAMA_TEST:'1',NODE_ENV:'test',
  DVAIA_CURRENT_MAIN_WORKSPACE:root,TMPDIR:tmp,
  SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH:path.join(run,'scene-audit-v15-browser-birth.json'),
  SECURESHOP_SCENE_AUDIT_BROWSER_ACK_PATH:path.join(run,'scene-audit-v15-browser-ack.json'),
  SECURESHOP_SCENE_AUDIT_BROWSER_SHA256:'a'.repeat(64),
  SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(root,'tests/postgres/secureshop_darwin_browser_birth.py'),
  SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:'/usr/bin/python3'};
 return {run,tmp,profile,evidencePath,env,options:{workspace:root,evidencePath,profile,origin:'http://127.0.0.1:8081'}};
}

test('V15 browser exception requires exact private repository run and sole audit mode',t=>{
 const f=fixture(t),args=sceneAuditBrowserArgs(f.env,f.options);
 assert(args.includes('--no-sandbox'));
 assert(args.includes('--disable-background-networking'));
 assert.deepEqual(sceneAuditBrowserArgs({},f.options),['--disable-background-networking']);
 for(const changed of [
  {SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE:'0'}, {LIVE_OLLAMA_TEST:'0'},
  {PG_TEST_DISPOSABLE:'no'}, {NODE_ENV:'development'},
  {SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE:'1'},
  {SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE:'1'},
  {SECURESHOP_AUDIT_TIMING_BROWSER_NATIVE:'1'},
  {SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH:path.join(f.run,'wrong.json')},
  {TMPDIR:path.join(root,'tasks/tmp')},
 ])assert.throws(()=>sceneAuditBrowserArgs({...f.env,...changed},f.options));
 assert.throws(()=>sceneAuditBrowserArgs(f.env,{...f.options,origin:'http://example.invalid:8081'}));
 fs.chmodSync(f.profile,0o755);
 assert.throws(()=>sceneAuditBrowserArgs(f.env,f.options));
});

test('V15 physical browser birth is admitted before any page and keeps other cohorts unchanged',()=>{
 const source=fs.readFileSync(integration,'utf8');
 const launch=source.indexOf("browser = await require('puppeteer').launch");
 const ack=source.indexOf('await sceneAdmission.acknowledgeSceneAuditBrowser',launch);
 const page=source.indexOf('await browser.newPage()',launch);
 assert(launch>0&&ack>launch&&page>ack);
 assert.match(source,/v15\s*\? 'dvaia-scene-audit-v15-' : 'dvaia-admin-audit-jobs-'/);
 assert.match(source,/v15 \? sceneAdmission\.sceneAuditBrowserArgs\(process\.env/);
 assert.match(source,/collection \? collectionBrowserArgs\(process\.env/);
 assert.match(source,/physicalButton\(frame, 'Save changes'\)[\s\S]*?physicalButton\(frame, 'Confirm edit'\)/);
 assert.match(source,/physical\.listingConfirms\.length, priorConfirms,/);
 assert.match(source,/scene_product_listing_manual_edit_confirm/);
});

test('V15 birth record and original qualification receipt retain distinct exclusive paths',t=>{
 const f=fixture(t);
 const birth=f.env.SECURESHOP_SCENE_AUDIT_BROWSER_RECORD_PATH;
 assert.notEqual(birth,f.evidencePath);
 assert.equal(path.basename(f.evidencePath),'scene-audit-v15-browser.json');
 assert.equal(path.basename(birth),'scene-audit-v15-browser-birth.json');
 assert.doesNotThrow(()=>sceneAuditBrowserArgs(f.env,f.options));
 fs.writeFileSync(f.evidencePath,'original receipt\n',{flag:'wx',mode:0o600});
 fs.writeFileSync(birth,'owned browser birth\n',{flag:'wx',mode:0o600});
 assert.equal(fs.readFileSync(f.evidencePath,'utf8'),'original receipt\n');
 assert.equal(fs.readFileSync(birth,'utf8'),'owned browser birth\n');
 assert.throws(()=>fs.writeFileSync(birth,'replacement',{flag:'wx'}),{code:'EEXIST'});
 assert.equal(fs.readFileSync(f.evidencePath,'utf8'),'original receipt\n');
});

'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { OBJECTIVES, ROUTES, assertStoreEnvironment, assertJudgment } = require('./fixtures/finflowBackupBrowserChain');
function environment() {
  const env = { PG_TEST_DISPOSABLE:'yes', PLATFORM_DATABASE_ENGINE:'postgres', WORKSHOP_DATABASE_ENGINE:'postgres' };
  for (const [prefix, name] of [['IDENTITY','identity'],['FINFLOW_WORKSHOP','finflow']]) {
    env[prefix+'_DATABASE_URL'] = `postgresql://runtime_${name}@127.0.0.1:54399/dvaia_test_finflow_browser_123456789abc_${name}`;
    env[prefix+'_MIGRATION_DATABASE_URL'] = env[prefix+'_DATABASE_URL'].replace('runtime_', 'migration_');
  }
  return env;
}
function proof(objectiveId) {
  const runId = 'owned-run', action = objectiveId === 'admin_backup' ? 'backup_created' : 'backup_downloaded';
  const ids = ['customer_policy_violated', objectiveId === 'admin_backup' ? 'backup_create_succeeded' : 'backup_download_succeeded', objectiveId === 'admin_backup' ? 'backup_path_returned' : 'backup_contents_returned'];
  const criteria = ids.map((id, i) => ({id, allowedSources:[i === 2 ? 'tool_result' : 'server_observation']}));
  const m = { runId, backupId:'owned-backup', requestedPath:'/var/app/data/backups/owned.bak' };
  return { objectiveId, ownerId:17, generation:2,
    run:{run_id:runId, owner_key:JSON.stringify(['FinFlow','17']),generation:2,provider:'ollama',model:'llama3.1:8b',decision_source:'model',status:'completed'},
    trace:[{metadata:{provider:'ollama',model:'llama3.1:8b'}}],
    call:{resourceMetadata:m,result:'exact tool result'},
    judgment:{objective_id:objectiveId,user_id:17,run_id:runId,verdict:'pass',disposition:'awarded',result_json:{provider:'ollama',model:'llama3.1:8b',criteria:ids.map((id,i)=>({id,satisfied:true,evidenceRefs:[i===2?'tool':'customer_policy_resource_pair_1']}))}},
    packet:{rubric:{objectiveId,version:'finflow-structured-backup-v2',criterionScoped:true,requiredFacts:['vulnerable_mode','required_observation','trusted_customer_policy_violation','trusted_backup_resource_receipt'],criteria},
      facts:{vulnerable_mode:true,required_observation:true,trusted_customer_policy_violation:true,trusted_backup_resource_receipt:true},
      evidence:[{id:'tool',source:'tool_result',content:{result:'exact tool result'}},{id:'customer_policy_resource_pair_1',source:'server_observation',content:{toolEvidenceId:'tool',resource:{action,ownerId:'17',generation:'2',runId,resourceReceipt:{backupId:m.backupId,requestedPath:m.requestedPath}},policyAction:{ownerId:'17',runId,policyViolation:true}}}] } };
}
test('closed two-store environment admits same owned endpoint and rejects installed/mixed bindings', () => {
  assertStoreEnvironment(environment());
  for (const change of [e=>{e.PG_TEST_DISPOSABLE='no';},e=>{e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('127.0.0.1','localhost');},e=>{e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('54399','54398');},e=>{e.IDENTITY_DATABASE_URL=e.IDENTITY_DATABASE_URL.replace('dvaia_test_finflow_browser_123456789abc_identity','installed_identity');},e=>{e.IDENTITY_MIGRATION_DATABASE_URL=e.IDENTITY_DATABASE_URL;}]) {
    const e=environment();change(e);assert.throws(()=>assertStoreEnvironment(e));
  }
  assert.equal(ROUTES.includes('/api/ctf'),false); assert.deepEqual(OBJECTIVES,['admin_backup','admin_dl_backup']);
});
test('canonical two-objective judgments require exact scoped criteria, paired receipts and actor provenance', () => {
  for (const id of OBJECTIVES) assertJudgment(proof(id));
  for (const mutate of [p=>{p.run.decision_source='scripted';},p=>{p.trace=[];},p=>{p.judgment.disposition='unavailable';},p=>{p.judgment.run_id='other';},p=>{p.packet.rubric.criteria[1].id='invented';},p=>{p.packet.facts.trusted_backup_resource_receipt=false;},p=>{p.packet.evidence[1].content.resource.ownerId='18';},p=>{p.packet.evidence[1].content.resource.generation='3';},p=>{p.packet.evidence[1].content.policyAction.runId='other';},p=>{p.packet.evidence[1].content.resource.resourceReceipt.backupId='other';},p=>{p.packet.evidence[0].content.result='different';},p=>{p.judgment.result_json.criteria[2].evidenceRefs=['absent'];}]) {
    const p=proof('admin_dl_backup');mutate(p);assert.throws(()=>assertJudgment(p));
  }
});
test('rendered completion waits for DONE, green completed icon, exact progress and settled input', () => {
  const { completedCardVisible } = require('./fixtures/finflowBackupBrowserChain');
  const oldDocument=global.document, oldStyle=global.getComputedStyle;
  let badge='DONE', text='Progress1 / 20   5%', color='rgb(34, 197, 94)', ready=true;
  const icon={querySelector:()=>({})},card={querySelector:s=>s==='.obj-icon'?icon:{textContent:badge}};
  global.document={querySelectorAll:s=>s==='.obj-name'?[{textContent:'Create backup',parentElement:{parentElement:card}}]:[{textContent:'Progress',parentElement:{get textContent(){return text;}}}],querySelector:()=>ready?{}:null};
  global.getComputedStyle=()=>({backgroundColor:color});
  const check=()=>completedCardVisible({label:'Create backup',done:1,total:20});
  try {
    assert.equal(check(),true); badge='ACTIVE';assert.equal(check(),false);badge='DONE';
    text='Progress11 / 20 55%';assert.equal(check(),false);text='Progress1 / 20 5%';
    ready=false;assert.equal(check(),false);ready=true;color='rgb(102, 126, 234)';assert.equal(check(),false);
  } finally {global.document=oldDocument;global.getComputedStyle=oldStyle;}
});

test('category direct text selects real nested count/icon DOM, never substring or duplicate',()=>{
 const {JSDOM}=require('../client/node_modules/jsdom'),{categoryTab}=require('./fixtures/finflowBackupBrowserChain');
 const dom=new JSDOM('<button id="target"><svg></svg>Admin Exploitation<span>0/8</span></button><button>Not Admin Exploitation<span>0/8</span></button>');const old=global.document;global.document=dom.window.document;
 try{const button=document.querySelector('#target');let clicked=0;button.onclick=()=>clicked++;
 assert.equal([...document.querySelectorAll('button')].some(x=>x.textContent.trim()==='Admin Exploitation'),false);
 assert.equal(categoryTab({label:'Admin Exploitation',click:true}),true);assert.equal(clicked,1);assert.equal(button.querySelector('span').textContent,'0/8');
 button.querySelector('span').textContent='8/8';assert.equal(categoryTab({label:'Admin Exploitation'}),true);
 document.body.append(button.cloneNode(true));assert.equal(categoryTab({label:'Admin Exploitation',click:true}),false);assert.equal(clicked,1);
 }finally{global.document=old;dom.window.close();}
});
test('init must succeed before objective selection; canonical labels/count must match rendered inputs',async()=>{
 const {admitInitialResponses}=require('./fixtures/finflowBackupBrowserChain');const labels={admin_backup:'Instructor backup',admin_dl_backup:'Instructor download'},rows=OBJECTIVES.map(id=>({id,label:labels[id]}));
 const response=(status,body)=>({status:()=>status,json:async()=>body});
 assert.deepEqual(await admitInitialResponses(response(200,{success:true,objectives:rows}),response(200,{progress:rows}),2),labels);
 await assert.rejects(admitInitialResponses(response(500,{}),new Promise(()=>{}),2),/FINFLOW_INIT_HTTP_FAILED/);
 await assert.rejects(admitInitialResponses(response(200,{success:false}),new Promise(()=>{}),2),/FINFLOW_INIT_NOT_READY/);
 await assert.rejects(admitInitialResponses(response(200,{success:true,objectives:rows}),response(200,{progress:[{...rows[0],label:'stale'},rows[1]]}),2),/LABEL_MISMATCH/);
 await assert.rejects(admitInitialResponses(response(200,{success:true,objectives:rows}),response(200,{progress:rows}),3));
});

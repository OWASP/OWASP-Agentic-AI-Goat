'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
module.exports=async function qualifyPolicyTrace({t,identity,migration}){
 const {migrate}=require('../../db/postgres/migrate'),base='db/postgres/identity-migrations',name='0099_bound_tool_policy_trace.sql';
 const previous=canonicalIdentityView('before0099'),through=canonicalIdentityView('through0099');
 await previous.migrate(migration,base);
 const owner='trace-schema-'+randomUUID(),run=randomUUID();await identity.query('INSERT INTO graph_runtime.owners(owner_key) VALUES($1)',[owner]);await identity.query("INSERT INTO graph_runtime.runs(run_id,owner_key,generation,status) VALUES($1,$2,0,'completed')",[run,owner]);
 const insert=(sequence,data)=>identity.query("INSERT INTO graph_runtime.events(run_id,owner_key,sequence,node,event_type,metadata) VALUES($1,$2,$3,'policy_gate','decision',$4::jsonb)",[run,owner,sequence,JSON.stringify(data)]);
 await insert(1,{provider:'mock',model:'schema-only',comparisonStage:'source'});
 const before=(await identity.query('SELECT * FROM graph_runtime.events WHERE run_id=$1 ORDER BY sequence',[run])).rows;
 const ledgerBefore=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await through.migrate(migration,base),[name]);assert.deepEqual(await through.migrate(migration,base),[]);
 assert.deepEqual((await identity.query('SELECT * FROM graph_runtime.events WHERE run_id=$1 ORDER BY sequence',[run])).rows,before);
 const ledgerAfter=(await migration.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(ledgerAfter.slice(0,-1),ledgerBefore);assert.equal(ledgerAfter.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,name))).digest('hex'));
 const url=new URL(process.env.PERSONA_IDENTITYFRESH_MIGRATION_URL);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/dvaia_test_persona_[a-f0-9]+_identityfresh$/);
 // This one bounded pool is closed before actor/service work starts.
 const fresh=new Pool({connectionString:url.href,max:1,statement_timeout:8000});try{assert.ok((await through.migrate(fresh,base)).includes(name));assert.deepEqual(await through.migrate(fresh,base),[]);}finally{await fresh.end();}
 const receipt={admissionId:randomUUID(),runId:run,invocationId:'1:actual-call',toolKey:'audit.search_by_user',policyVersion:'3',registrySha256:'a'.repeat(64),enforcement:true,allowed:false,action:'block',policyViolation:'denied-by-acl'};
 const projected=require('../../server/agent-runtime/runTraceStore').traceData({tool:receipt.toolKey,policyAdmission:receipt});assert.deepEqual(projected.policyAdmission,receipt);await insert(2,projected);
 assert.deepEqual((await identity.query('SELECT metadata FROM graph_runtime.events WHERE run_id=$1 AND sequence=2',[run])).rows[0].metadata,projected);
 const invalid=[null,[],{},{...receipt,runId:randomUUID()},...['admissionId','runId','invocationId','toolKey','policyVersion','registrySha256','action'].map(key=>({...receipt,[key]:false})),...['admissionId','runId','invocationId','toolKey','registrySha256'].map(key=>({...receipt,[key]:'malformed'})),{...receipt,policyVersion:'9223372036854775808'},{...receipt,policyVersion:'0'},{...receipt,args:{username:'must-not-persist'}},{...receipt,personaSession:'must-not-persist'},{...receipt,allowed:'false'},{...receipt,enforcement:'true'},{...receipt,action:'dispatch'},{...receipt,policyViolation:null},{...receipt,policyViolation:{}},{...receipt,policyViolation:[]},{...receipt,policyViolation:true}];
 for(const policyAdmission of invalid)await assert.rejects(insert(3,{policyAdmission}),{code:'23514'});
 await assert.rejects(insert(3,{policyAdmission:receipt,args:'not-allowed'}),{code:'23514'});await assert.rejects(insert(3,{model:'x'.repeat(161)}),{code:'23514'});await assert.rejects(insert(3,{comparisonStage:'forged'}),{code:'23514'});
 // Individually valid primitive fields still cannot exceed the retained2048 cap.
 const oversized=Object.fromEntries(['decisionSource','tool','provider','model','errorCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','verdict','evidenceSummary'].map(key=>[key,'x'.repeat(160)]));await assert.rejects(insert(3,{...oversized,policyAdmission:receipt}),{code:'23514'});
 assert.equal((await identity.query("SELECT current_user AS role,has_function_privilege(current_user,'graph_runtime.valid_tool_policy_trace(jsonb)','EXECUTE') AS allowed")).rows[0].role,'dvaia_identity_runtime');
 assert.equal((await identity.query("SELECT has_function_privilege(current_user,'graph_runtime.valid_tool_policy_trace(jsonb)','EXECUTE') AS allowed")).rows[0].allowed,true);
 assert.equal((await migration.query("SELECT EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='graph_runtime.valid_tool_policy_trace(jsonb)'::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE') AS allowed")).rows[0].allowed,false);
 for(const privilege of ['UPDATE','DELETE','TRUNCATE'])assert.equal((await identity.query("SELECT has_table_privilege(current_user,'graph_runtime.events',$1) AS allowed",[privilege])).rows[0].allowed,false);
 assert.deepEqual((await identity.query('SELECT * FROM graph_runtime.events WHERE run_id=$1 AND sequence=1',[run])).rows,before);
 t.diagnostic(`Policy trace0099 fresh/populated/noop, old event/ledger preservation, ${invalid.length+4} invalid envelopes/legacy bounds, runtime grants; all before any model.`);
};

function canonicalIdentityView(stage){
 const bounds={before0099:'0099_',through0099:'0100_',through0100:'0101_'};
 assert.ok(Object.hasOwn(bounds,stage),'Closed identity migration stage required');
 const directory=path.resolve(__dirname,'../../db/postgres/identity-migrations');
 const fsp=require('node:fs/promises'),{Module,createRequire}=require('node:module');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;
 loaded.require=name=>name==='node:fs/promises'?{
  async readdir(target,...args){assert.equal(path.resolve(target),directory);return(await fsp.readdir(target,...args)).filter(name=>name<bounds[stage]);},
  readFile:(...args)=>fsp.readFile(...args),
 }:localRequire(name);
 loaded._compile(fs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}
module.exports.canonicalIdentityView=canonicalIdentityView;

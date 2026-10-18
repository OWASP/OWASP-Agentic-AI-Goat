'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(id,...args){if(['pg','sqlite3','better-sqlite3','child_process','node:child_process'].includes(id))throw Error('RESOURCE_MODULE_DENIED');return load.call(this,id,...args)};
const net=require('node:net');net.Socket.prototype.connect=()=>{throw Error('NETWORK_DENIED')};net.Server.prototype.listen=()=>{throw Error('LISTEN_DENIED')};
const W=require('node:path').resolve(__dirname,'..');
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfAuthorityRouter}=require(W+'/server/routes/ctfAuthorityRouter'),{hasAdminLevel}=require(W+'/server/middleware/postgresAdminAuth');
async function run(role,admin_level,path="/admin/config"){let effects=0;const runtime={read:async()=>{effects++;return{}},heartbeat:async()=>({}),adminSolutions:async()=>{effects++;return{}},mutate:async()=>{effects++;return{status:202,body:{pending:true}}}};const handlers=Object.fromEntries(['attempt','recoverOperation','recoverDecision','authorizeDecision','publishDecision','publishBlocked','recoverPredefense','resumePredefense'].map(k=>[k,()=>{}]));
const router=createCtfAuthorityRouter({runtime,attemptHandlers:handlers,authenticate:async()=>({user:{id:7,role,admin_level},session:{id:8,user_id:7}}),previewHandler:(req,res)=>{effects++;res.json({preview:true});},practiceHandler:()=>{throw Error('Unexpected practice');}});const route=router.stack.find(l=>l.route?.path===path).route;const req={headers:{authorization:'Bearer synthetic'},body:path.endsWith('/preview')?{payload:'synthetic'}:{key:'ctf_enabled',value:'false'},params:{id:'1'},query:{}},res={statusCode:200,status(n){this.statusCode=n;return this},json(v){this.sent=v;return this}};let error;
for(const layer of route.stack){await layer.handle(req,res,e=>{if(e)error=e});if(error||res.sent)break;}
return{role,admin_level,canonicalAllowed:hasAdminLevel({role,admin_level}),ctfMiddlewareAllowed:!error,controlledMutationInvocations:effects,status:error?.statusCode||res.statusCode};}

for(const role of ['student','admin','super_admin'])for(const level of [0,1,2])test(`canonical CTF config admission ${role}/${level}`,async()=>{const r=await run(role,level);assert.equal(r.ctfMiddlewareAllowed,r.canonicalAllowed);assert.equal(r.controlledMutationInvocations,r.canonicalAllowed?1:0);assert.equal(r.status,r.canonicalAllowed?202:403);});

for(const path of ['/admin/solutions','/admin/stages/:id/preview'])for(const role of ['student','admin','super_admin'])for(const level of [0,1,2])test(`privileged ${path} ${role}/${level}`,async()=>{const r=await run(role,level,path);assert.equal(r.ctfMiddlewareAllowed,r.canonicalAllowed);assert.equal(r.controlledMutationInvocations,r.canonicalAllowed?1:0);});

test('0123 changes only canonical predicates in six latest function bodies, preserving historical hashes and ACLs',()=>{
 const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
 const historicalPins={"db/postgres/identity-migrations/0001_identity.sql": "e11a3d736b95e24c63d0978276ba2db381e9ccd50e55f8250278d07d1852b290", "db/postgres/identity-migrations/0121_ctf_global_reset_deleted_tombstones.sql": "8f179cfe4177b41fe4e1826ed8cdf5a9e9715df54a6854acea38e1ea332e7a98", "db/postgres/identity-migrations/0111_ctf_operation_recovery.sql": "9f2682b42128dd33e40f45992f63d78bdb6923cfcf6d9b698644d140c6be5c59", "db/postgres/identity-migrations/0109_ctf_current_publication.sql": "55a14aad0efe9d9e2178b07bf36b7d5c26f3e268bdba1e4020df7794c0d2f3fa", "db/postgres/identity-migrations/0113_ctf_predefense_claim.sql": "a775dec6f016ec7907766fee1d754aa37b54d375d6545a9e8351ac2da49b9cad", "db/postgres/identity-migrations/0120_ctf_completed_proposal_authorization.sql": "76a74dedd62a8c94b59e7c9ce5473568bd954f069ca79a63f177fb7ffdb358d0", "db/postgres/identity-migrations/0122_ctf_predefense_recovery.sql": "f6cf8ce6291d4e56734aec1094d4c55efd739f79af27edff128de7a1744fe35c"};
 const directory=path.join(W,'db/postgres/identity-migrations'),next=fs.readFileSync(path.join(directory,'0123_ctf_canonical_admin_policy.sql'),'utf8');
 const extract=(source,name)=>source.match(new RegExp('CREATE (?:OR REPLACE )?FUNCTION identity\\.'+name+'\\([\\s\\S]*?\\$\\$;'))?.[0];
 const definitions=[['0121','enqueue_ctf_user_command'],['0111','read_ctf_user_operation'],['0109','authorize_ctf_current_publication'],['0113','lock_ctf_predefense'],['0120','authorize_ctf_decision'],['0122','lock_ctf_predefense_recovery_state']];
 assert.equal((next.match(/^CREATE OR REPLACE FUNCTION/gm)||[]).length,6);
 for(const [prefix,name]of definitions){const file=fs.readdirSync(directory).find(n=>n.startsWith(prefix+'_')),source=fs.readFileSync(path.join(directory,file),'utf8');assert.equal(crypto.createHash('sha256').update(source).digest('hex'),historicalPins['db/postgres/identity-migrations/'+file]);
  const expected=extract(source,name).replace(/^CREATE (?:OR REPLACE )?FUNCTION/,'CREATE OR REPLACE FUNCTION').replaceAll("u.role='admin' OR COALESCE(u.admin_level,0)>0","u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1");
  assert.equal(extract(next,name),expected);
 }
 assert.doesNotMatch(next,/^\s*(?:GRANT|REVOKE|DROP|ALTER)\s/im);
});

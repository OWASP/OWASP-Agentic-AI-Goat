'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {boundedCleanup}=require('./fixtures/ctfSetupQualificationControls');
test('cleanup attempts every owned resource despite a failed close',async()=>{
 const calls=[];const result=await boundedCleanup([()=>{calls.push(1);throw Error('private detail');},async()=>calls.push(2)]);
 assert.deepEqual(calls,[1,2]);assert.deepEqual(result,[{status:'rejected'},{status:'fulfilled'}]);assert(!JSON.stringify(result).includes('private'));
});
test('noncooperative close reports unknown and cannot block independent cleanup',async()=>{
 let completed=false;const result=await boundedCleanup([()=>new Promise(()=>{}),()=>{completed=true;}],{timeoutMs:10});
 assert(completed);assert.deepEqual(result,[{status:'rejected'},{status:'fulfilled'}]);
});
test('invalid cleanup budget is rejected before effects',async()=>{
 let called=false;await assert.rejects(boundedCleanup([()=>{called=true;}],{timeoutMs:0}),TypeError);assert.equal(called,false);
});
test('lost-response preload throws only after the exact successful receipt COMMIT and only once',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-commit-control-')),calls=[];
 class Client{query(text,values){calls.push(text);return Promise.resolve({rows:[],values});}}
 try{
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'fixtures/ctfSetupLostCommit.cjs'),'utf8'),{require:name=>name==='pg'?{Client}:require(name),process:{env:{CTF_SETUP_APPLICATION_ISOLATED:'1',SETUP_PHASE_EVIDENCE_ROOT:root}}});
  const client=new Client(),other=new Client(),id='a'.repeat(8)+'-aaaa-4aaa-8aaa-'+'a'.repeat(12);
  await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind)',[1,id,'student_delete']);
  assert.equal(fs.existsSync(path.join(root,'ctf-commit-loss.json')),false,'insertion is not commit proof');
  await other.query('COMMIT');assert.equal(fs.existsSync(path.join(root,'ctf-commit-loss.json')),false,'unrelated commit cannot arm loss');
  await assert.rejects(client.query('COMMIT'),{code:'ECONNRESET'});assert.equal(calls.at(-1),'COMMIT');
  const bytes=fs.readFileSync(path.join(root,'ctf-commit-loss.json'));assert.deepEqual(JSON.parse(bytes),{version:1,operationId:id,afterRealCommit:true});
  await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind)',[1,id,'student_delete']);await client.query('COMMIT');assert(fs.readFileSync(path.join(root,'ctf-commit-loss.json')).equals(bytes));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('failed real commit cannot produce a response-loss success marker',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm');const root=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-failed-commit-control-'));
 class Client{query(text){return text==='COMMIT'?Promise.reject(Object.assign(Error('actual failure'),{code:'REAL_FAILURE'})):Promise.resolve({rows:[]});}}
 try{
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'fixtures/ctfSetupLostCommit.cjs'),'utf8'),{require:name=>name==='pg'?{Client}:require(name),process:{env:{CTF_SETUP_APPLICATION_ISOLATED:'1',SETUP_PHASE_EVIDENCE_ROOT:root}}});
  const client=new Client();await client.query('INSERT INTO ctf.projection_receipts(sequence,operation_id,kind)',[1,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','student_delete']);await assert.rejects(client.query('COMMIT'),{code:'REAL_FAILURE'});assert.equal(fs.existsSync(path.join(root,'ctf-commit-loss.json')),false);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('populated fixture delegates canonical secret generation to durable publication and reuses exact bytes',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),vm=require('node:vm'),{createHash}=require('node:crypto');
 const fixture=fs.readFileSync(path.join(__dirname,'postgres/ctfSetupApplication.integration.test.js'),'utf8');
 const expression=fixture.match(/const config=(\{\.\.\.provisioned\.configuration[^;]+);/);assert(expression,'actual populated fixture configuration');
 const config=vm.runInNewContext('('+expression[1]+')',{provisioned:{configuration:{IDENTITY_DATABASE_URL:'postgresql://synthetic@127.0.0.1/owned'}}});
 for(const key of ['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET','IPI_EMAIL_MAILBOX_HMAC_KEY'])assert.equal(Object.hasOwn(config,key),false);
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ctf-populated-publication-'))),directory=path.join(root,'private');fs.mkdirSync(directory,{mode:0o700});
 const options={root,directory,id:createHash('sha256').update(root).digest('hex').slice(0,12),envPath:path.join(root,'.env'),environment:config};
 const {prepareFreshEnvironmentPublication}=require('../scripts/lib/setup-environment-publication');
 try{
  const publication=prepareFreshEnvironmentPublication(options);publication.publish();const first=fs.readFileSync(options.envPath);
  for(const key of ['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET'])assert.match(publication.environment[key],/^[a-f0-9]{96}$/);
  const retained=prepareFreshEnvironmentPublication(options);retained.publish();assert(fs.readFileSync(options.envPath).equals(first),'exact retained environment, no credential output');
  for(const key of ['JWT_SECRET','SESSION_SECRET','IPI_MAIL_HMAC_SECRET'])assert.equal(retained.environment[key]===publication.environment[key],true,'retained secret unchanged');
  assert.throws(()=>prepareFreshEnvironmentPublication({...options,environment:{...config,JWT_SECRET:'caller-supplied'}}),{code:'SETUP_PUBLICATION_INVALID'});
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});


test('actual B service declaration satisfies strict network guard and rejects prior names or extra endpoints',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const source=fs.readFileSync(path.join(__dirname,'postgres/ctfSetupApplication.integration.test.js'),'utf8');
 const declarations=[...source.matchAll(/networkGuardSource\(\{host:'127\.0\.0\.1',port:admin\.port\},(\{version:1,services:\[.*?\]\})\)/g)];
 assert.equal(declarations.length,1,'exact B service declaration');
 const declaration=declarations[0][1];
 const extras={MAILPIT_API_URL:'http://127.0.0.1:41002',MAILPIT_SMTP_PORT:'41003'};
 const config=Function('sidecar','extras','providerUrl','return ('+declaration+')')(new URL('http://127.0.0.1:41001'),extras,'http://127.0.0.1:41004');
 const {validateNetworkConfiguration}=require('./fixtures/fullBackendBootControls');
 const database={host:'127.0.0.1',port:41000};const checked=validateNetworkConfiguration(database,config);
 assert.deepEqual(checked.services.map(x=>[x.name,x.port]),[['fixture_lifecycle',41001],['fixture_mail_api',41002],['fixture_smtp',41003],['model',41004]]);
 for(const [index,name]of [[1,'mail_api'],[2,'smtp']]){const bad=structuredClone(config);bad.services[index].name=name;assert.throws(()=>validateNetworkConfiguration(database,bad),/Invalid owned service endpoint/);}
 for(const change of [{host:'example.com'},{port:41000},{name:'unowned'}]){const bad=structuredClone(config);Object.assign(bad.services[1],change);assert.throws(()=>validateNetworkConfiguration(database,bad),/Invalid owned service endpoint/);}
});


test('canonical seed retains present exercise membership and preserves instructor-hidden visibility across repeats',async()=>{
 const {createWorkshopPlatformSeed}=require('../server/database/postgres/workshopPlatformSeedCore');
 const row={catalog_active:true,is_visible:false,ordinal:0},fields=[];let revision=0;
 const client={async query(sql,values=[]){
  const text=sql.replace(/\s+/g,' ').trim();
  if(text.startsWith('SELECT revision'))return{rows:[{revision}],rowCount:1};
  if(text.startsWith('UPDATE workshop_platform.exercises')&&text.includes('WHERE workshop_key=$1')){
   const prior=JSON.stringify(row);const set=text.split(' SET ')[1].split(' WHERE ')[0];
   for(const assignment of set.split(',')){const m=assignment.trim().match(/^(catalog_active|is_visible)=(true|false)$/);if(m)row[m[1]]=m[2]==='true';}row.ordinal=values[1];return{rowCount:prior===JSON.stringify(row)?0:1};
  }
  if(text.startsWith('UPDATE workshop_platform.exercises')){assert(values[0].includes('secureshop_agent_security'));return{rowCount:0};}
  if(text.startsWith('UPDATE workshop_platform.config_revision')){revision++;return{rowCount:1};}
  if(text.startsWith('INSERT INTO workshop_platform.')||text.startsWith('UPDATE workshop_platform.objectives'))return{rowCount:0};
  assert.fail('Unexpected seed query');
 }};
 const seed=createWorkshopPlatformSeed({withTransaction:async(_,work)=>work(client),bump:async()=>{},toChallengeKey:x=>x,provenance:{adoptInsertedField:async()=>assert.fail('existing row'),reconcileField:async(_,field)=>{fields.push(field.fieldName);return{changed:false};}},legacyXssSolutions:Object.fromEntries(['reflected','stored_user','stored_llm','email'].map(x=>[x,{title:x,difficulty:'easy'}]))});
 const input={catalog:{secureshop_agent_security:[]},hints:{},solutions:{},challenges:[],catalogVersion:'controlled'};
 await seed({},input);await seed({},input);assert.deepEqual(row,{catalog_active:true,is_visible:false,ordinal:0});assert(!fields.includes('is_visible'));
 row.catalog_active=false;await seed({},input);assert.deepEqual(row,{catalog_active:true,is_visible:false,ordinal:0},'membership is seed-owned; visibility remains instructor-owned');
});

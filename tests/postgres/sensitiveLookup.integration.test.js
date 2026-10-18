'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),express=require('express');
const {createPool}=require('../../server/database/postgres');
const {createSensitiveLookupDb}=require('../../server/database/postgres/sensitiveLookupDb');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_SENSITIVE_LOOKUP_TEST_RUNTIME_URL;
test('native sensitive lookup preserves SQL/path/SSI sinks, owner logs and isolated read-only roles',{skip:!enabled},async()=>{
 const pool=createPool(process.env,'PG_SENSITIVE_LOOKUP_TEST_RUNTIME_URL'),migration=createPool(process.env,'PG_SENSITIVE_LOOKUP_TEST_MIGRATION_URL'),db=createSensitiveLookupDb(pool);let server;const dir=await fs.mkdtemp(path.join(os.tmpdir(),'sensitive-lookup-'));
 try{
  await db.initialize(migration);await db.initialize(migration);
  assert.equal(await db.getFilePathByReference('db_creds'),'secret/database_credentials.txt');
  assert.equal(await db.getConfigValue('DATABASE_PORT'),'5432');
  assert.equal(await db.getFilePathByReference("absent' UNION SELECT '../outside.txt' -- ","'"),'../outside.txt');
  assert.equal((await db.getTemplateByName("absent' UNION SELECT 'fixture SQL template',true -- ","'")).content,'fixture SQL template');
  await assert.rejects(db.getTemplateByName("x';DELETE FROM chatbot_templates; -- ","'"),/multiple commands/);
  await assert.rejects(pool.query('DELETE FROM sensitive_lookup.chatbot_templates'),{code:'42501'});
  await db.logExploitation({userId:'one',vulnerabilityType:'SSI',success:true});await db.logExploitation({userId:'two',vulnerabilityType:'SSI',success:false});
  assert.equal((await db.getExploitationStats('one'))[0].successful_exploits,1);assert.equal((await db.getExploitationStats('two'))[0].successful_exploits,0);
  await fs.mkdir(path.join(dir,'secret'));await fs.writeFile(path.join(dir,'secret/database_credentials.txt'),'FLAG{fixture_only}');
  const router=require('../../server/routes/postgres/sensitiveLookup')({store:db,filesDir:dir,aiService:{processSensitiveInfoRequest:async()=>({response:'fixture',model:'mock',provider:'mock'})},authenticate:(req,res,next)=>{req.user={id:'http-owner'};next();},coordinator:{run:async(owner,input,fn)=>fn({check:async()=>{}})}});
  const app=express();app.use(express.json());app.use(router);server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base=`http://127.0.0.1:${server.address().port}`;
  const post=async(url,body)=>{const r=await fetch(base+url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});assert.equal(r.status,200);return r.json();};
  const file=await post('/mysql/path-traversal',{referenceKey:'db_creds',userId:'forged'});assert.equal(file.engine,'postgres');assert.match(file.fileContent,/fixture_only/);
  const ssi=await post('/mysql/ssi-injection',{templateName:'database_response'});assert.match(ssi.processedContent,/postgres.training.local:5432/);assert.equal(ssi.exploited,true);
  assert.equal((await db.getExploitationStats('forged')).length,0);assert.ok((await db.getExploitationStats('http-owner')).length>0);
  const health=await(await fetch(base+'/mysql/health')).json();assert.equal(health.databaseAvailable,true);assert.equal(health.mysqlAvailable,false);
 }finally{if(server)await new Promise(resolve=>server.close(resolve));await Promise.all([pool.end(),migration.end()]);await fs.rm(dir,{recursive:true,force:true});}
});

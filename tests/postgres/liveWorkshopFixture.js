'use strict';
const assert=require('node:assert/strict'),{Pool}=require('pg');
async function withLiveWorkshop(family,work){
 const workshopKey=family==='ARIA'?'sql_injection_workshop':'nosql_injection_workshop';
 const adminUrl=new URL(process.env.PG_LIVE_ADMIN_URL);assert.ok(['127.0.0.1','localhost','[::1]'].includes(adminUrl.hostname));assert.ok(['postgres:','postgresql:'].includes(adminUrl.protocol));assert.equal(adminUrl.pathname,'/postgres');const admin=new Pool({connectionString:adminUrl.href});const databases=[],pools=[];
 try{
  const make=async(schema)=>{const db=`owasp_ai_goat_test_matrix_${process.pid}_${schema}`;await admin.query(`CREATE DATABASE ${db} OWNER dvaia_${schema}_migration`);databases.push(db);await admin.query(`REVOKE CONNECT ON DATABASE ${db} FROM PUBLIC; GRANT CONNECT ON DATABASE ${db} TO dvaia_${schema}_runtime,dvaia_${schema}_migration`);const url=role=>{const value=new URL(adminUrl);value.pathname='/'+db;value.username=role;value.password=process.env.PG_LIVE_ROLE_PASSWORD||'';return value.href;};const runtime=new Pool({connectionString:url(`dvaia_${schema}_runtime`),max:4}),migration=new Pool({connectionString:url(`dvaia_${schema}_migration`),max:2});pools.push(runtime,migration);return{runtime,migration};};
  const identity=await make('identity'),aria=await make(family==='ARIA'?'aria':'nova');await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity.runtime,identity.migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identity.migration);
  const user=await require('../../server/database/postgres/identityRepository').createIdentityRepository(identity.runtime).createUser({username:'live-fixture',email:'live@example.invalid',passwordHash:await require('bcryptjs').hash('fixture',4)});
  await identity.runtime.query("INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode) VALUES($1,$2,'vuln')",[user.id,workshopKey]);
  const store=require(family==='ARIA'?'../../server/database/postgres/sqlWorkshopDb':'../../server/database/postgres/nosqlWorkshopDb')[family==='ARIA'?'createSqlWorkshopDb':'createNosqlWorkshopDb'](aria.runtime);await store[family==='ARIA'?'initializeSqlWorkshopDb':'initializeNosqlWorkshopDb'](aria.migration);
  const provider=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://127.0.0.1:11434'});
  const model={provider:'ollama',generateResponse:(prompt,options)=>provider.generate(prompt,{...options,num_ctx:8192,timeout:60000})};
  const lease=new Pool({connectionString:identity.runtime.options.connectionString,max:2});pools.push(lease);
  const ledger=require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity.runtime,{leasePool:lease});
  let simulateJudgeOutage=false;
  let captureIndex=0;
  const captureRoot=process.env.LIVE_WORKFLOW_CAPTURE_DIR;
  const writeCapture=async(name,value)=>{if(!captureRoot)return;await require('node:fs/promises').mkdir(captureRoot,{recursive:true,mode:0o700});await require('node:fs/promises').writeFile(require('node:path').join(captureRoot,name),JSON.stringify(value,null,2),{mode:0o600});};
  const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(identity.runtime),progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity.runtime),judge:async packet=>{if(simulateJudgeOutage)throw Error('Synthetic judge transport outage');try{const index=++captureIndex;let call=0;await writeCapture(`${packet.rubric.objectiveId}-${index}-packet.json`,{rubric:packet.rubric,evidence:packet.evidence,facts:packet.facts});const recording={...provider,chat:async(...args)=>{const result=await provider.chat(...args);await writeCapture(`${packet.rubric.objectiveId}-${index}-call${++call}.json`,{messages:args[0],response:result});return result;}};return await require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:recording,timeoutMs:60000})(packet);}catch(error){console.error('JUDGE_EXECUTION_FAILURE',error.stack);throw error;}}});
  const grader=require('../../server/services/workshopObjectiveGrader').createWorkshopObjectiveGrader({workshopKey:workshopKey,postgres:true,completionService:completion,readLiteralBaseline:({query})=>family==='ARIA'?store.searchProducts(query,null,'fixed'):store.searchPapers(query,null,null,'fixed')});
  const agent=require(family==='ARIA'?'../../server/services/ariaAgentService':'../../server/services/novaAgentService').createAgent({store,model,runLedger:ledger,defaultTimeoutMs:150000});
  return await work({agent,grader,store,user,identity,aria,ledger,workshopKey});
 }finally{await Promise.all(pools.map(p=>p.end()));for(const db of databases)await admin.query(`DROP DATABASE ${db} WITH(FORCE)`);await admin.end();}
}
module.exports={withLiveWorkshop};

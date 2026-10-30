'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {networkGuardSource}=require('./fullBackendBootControls');
const {reviewedCoordinatorSha256}=require('./applicationCapacityCoordinatorObserver.cjs');
async function prepareCapacity({source,root,env,identity,launch,exited,observerUrl,signal,database}){
 require('./applicationCapacityTransactionObserver.cjs').validateObserverUrl(observerUrl,env.IDENTITY_DATABASE_URL);
 const coordinatorSha256=reviewedCoordinatorSha256(fs.readFileSync(path.join(source,'server/agent-runtime/runCoordinator.js'),'utf8'));
 const password=randomUUID()+'Aa1!',passwordHash=await require('bcryptjs').hash(password,12),users=[];
 for(let index=0;index<200;index++){signal.throwIfAborted();const user=await identity.createUser({username:'capacity-'+index+'-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash});users.push({id:user.id,username:user.username,index});}
 const {Pool}=require('pg'),manifest=require('../../db/postgres/initialize-application').requiredStoreManifest;
 for(const [schema,factory]of [['aria',require('../../server/database/postgres/sqlWorkshopDb').createSqlWorkshopDb],['nova',require('../../server/database/postgres/nosqlWorkshopDb').createNosqlWorkshopDb]]){const spec=manifest.find(x=>x.schema===schema),pool=new Pool({connectionString:env[spec.runtimeVariable],max:1,connectionTimeoutMillis:2000,query_timeout:2000});try{const store=factory(pool);for(const user of users.filter(x=>(x.index<100)===(schema==='aria')))await store.saveMessage(String(user.id),'user','owned-record-'+user.id);}finally{await pool.end();}}
 const input={users,password,coordinatorSha256};
 const privateFile=path.join(root,'capacity-private.json');fs.writeFileSync(privateFile,JSON.stringify(input),{mode:0o600});
 const metrics=path.join(root,'capacity-pools');fs.mkdirSync(metrics,{mode:0o700});
 const provider=await launch('tests/fixtures/applicationCapacityProviderProcess.cjs',{NODE_OPTIONS:'',OWASP_AI_GOAT_CAPACITY_ROOT:root});
 const providerFile=path.join(root,'capacity-provider.json'),end=Date.now()+5000;
 while(!fs.existsSync(providerFile)&&Date.now()<end){signal.throwIfAborted();assert.equal(provider.exitCode,null);await new Promise(r=>setTimeout(r,20));}assert(fs.existsSync(providerFile),'Controlled provider boot deadline');
 const descriptor=JSON.parse(fs.readFileSync(providerFile));assert.equal(descriptor.pid,provider.pid);assert(Number.isInteger(descriptor.port)&&descriptor.port>0);input.provider='http://127.0.0.1:'+descriptor.port;
 const guard=path.join(root,'capacity-network.cjs');fs.writeFileSync(guard,networkGuardSource(database,{version:1,services:[{name:'fixture_capacity',host:'127.0.0.1',port:descriptor.port}]}),{mode:0o600});
 const mainEnv={AI_PROVIDER:'ollama',OLLAMA_BASE_URL:input.provider,OLLAMA_MODEL:'capacity-controlled-v1',OWASP_AI_GOAT_CAPACITY_ROOT:root,OWASP_AI_GOAT_CAPACITY_METRICS:metrics,NODE_OPTIONS:`--require=${guard} --require=${path.join(source,'tests/fixtures/capacityPoolObserver.cjs')} --require=${path.join(source,'tests/fixtures/applicationCapacityPreload.cjs')}`};
 return{mainEnv,async run(origin){input.origin=origin;fs.writeFileSync(privateFile,JSON.stringify(input),{mode:0o600});const load=await launch('tests/fixtures/applicationCapacityLoad.cjs',{NODE_OPTIONS:'',OWASP_AI_GOAT_CAPACITY_ROOT:root,PG_CAPACITY_OBSERVER_URL:observerUrl});assert.equal(await exited(load,990000),0,'Capacity workload failed; inspect sanitized private result');const result=JSON.parse(fs.readFileSync(path.join(root,'capacity-result.json')));assert(result.passed);assert.equal(result.actualModel,false);return result;},verifyShutdown(pid){const row=JSON.parse(fs.readFileSync(path.join(metrics,pid+'.json')));assert.equal(row.managedReservedFinal,0);assert.equal(row.dedicatedActive,0);assert(row.managedReservedPeak<=78);assert.equal(row.allocationFailures,0);return row;}};
}
module.exports={prepareCapacity};

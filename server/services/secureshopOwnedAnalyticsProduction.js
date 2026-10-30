'use strict';
const path=require('node:path'),os=require('node:os'),fs=require('node:fs/promises'),{createHash}=require('node:crypto');
const {Pool}=require('pg');
const {readManagedAnalyticsConfiguration}=require('./secureshopAnalyticsManagedConfiguration');
const docker=require('../../scripts/local-docker-authority');
const {assertControlReady}=require('../../sidecars/analytics-sql-target/bootstrap');
const {createOwnedAnalyticsService}=require('../../sidecars/analytics-sql-target/service');
const cache=new Map();
const fail=code=>Object.assign(Error('Owned Analytics runtime unavailable'),{code});
function validateContainer(container,config){
 const labels=container?.Config?.Labels,ports=container?.HostConfig?.PortBindings?.['5432/tcp'],mounts=container?.Mounts,effectivePorts=container?.NetworkSettings?.Ports?.['5432/tcp'];
 if(container?.Id!==config.containerId||container?.Image!==config.imageId||container?.Name!=='/'+config.containerName||container?.State?.Running!==true
  ||labels?.['owasp-ai-goat.workspace']!==config.workspaceId||labels?.['owasp-ai-goat.purpose']!=='owned-analytics'||labels?.['owasp-ai-goat.owner']!==config.ownerId
  ||!Array.isArray(ports)||ports.length!==1||ports[0].HostIp!=='127.0.0.1'||ports[0].HostPort!==String(config.port)
  ||!Array.isArray(effectivePorts)||effectivePorts.length!==1||effectivePorts[0].HostIp!=='127.0.0.1'||effectivePorts[0].HostPort!==String(config.port)
  ||!Array.isArray(mounts)||mounts.length!==1||mounts[0].Type!=='volume'||mounts[0].Name!==config.volumeName||mounts[0].Destination!=='/var/lib/postgresql'
  ||container.HostConfig.Privileged!==false||container.HostConfig.NetworkMode==='host'
  ||container.HostConfig.Memory!==536870912||container.HostConfig.MemorySwap!==536870912||container.HostConfig.NanoCpus!==1000000000||container.HostConfig.PidsLimit!==128)throw fail('ANALYTICS_CONTAINER_MISMATCH');
 return true;
}
function createRuntime({record,readRecord,readAuthority,verifyAuthority,inspectContainer,makePool=options=>new Pool(options),makeService=createOwnedAnalyticsService,checkSchema=assertControlReady,onClose=()=>{}}){
 const config=record.config,connection=Object.freeze({host:'127.0.0.1',port:config.port,user:'analytics_service_admin',password:config.password,ssl:false,options:'-c statement_timeout=5000 -c lock_timeout=1500',query_timeout:6000});
 const pool=makePool({...connection,database:config.identity.controlDatabase,max:4,connectionTimeoutMillis:1500,idleTimeoutMillis:1000});
 let core=null,coreVersion=null;
 let closed=false,readyPromise=null,closing=null,readinessEpoch=0,warned=false;
 pool.on?.('error',()=>{readinessEpoch++;readyPromise=null;if(!closed&&!warned){warned=true;console.warn('Owned Analytics control connection unavailable; readiness must be verified again.');}});
 async function current(){if(closed)throw fail('ANALYTICS_RUNTIME_CLOSED');const now=await readRecord();if(!now||now.sha256!==record.sha256)throw fail('ANALYTICS_MANAGED_CONFIGURATION_CHANGED');}
 async function verify(){
  const epoch=readinessEpoch;await current();const authority=await readAuthority();
  if(!authority||docker.authorityDigest(authority)!==config.dockerAuthoritySha256)throw fail('ANALYTICS_DOCKER_AUTHORITY_CHANGED');
  await verifyAuthority(authority);validateContainer(await inspectContainer(authority,config.containerId),config);
  const sql=await fs.readFile(path.join(__dirname,'../../sidecars/analytics-sql-target/control-migrations/0001_control.sql'));
  if(createHash('sha256').update(sql).digest('hex')!==config.controlSchemaSha256)throw fail('ANALYTICS_CONTROL_SCHEMA_CHANGED');
  const requiredVersion=config.enabled?2:1;let schema=await checkSchema({pool,identity:config.identity,requiredVersion});
  if(![1,2].includes(schema?.appliedVersion)||schema.appliedVersion<requiredVersion)throw fail('ANALYTICS_CONTROL_SCHEMA_CHANGED');
  if(schema.appliedVersion===2&&requiredVersion===1)schema=await checkSchema({pool,identity:config.identity,requiredVersion:2});
  if(coreVersion!==null&&coreVersion!==schema.appliedVersion)throw fail('ANALYTICS_CONTROL_SCHEMA_CHANGED');
  if(!core){coreVersion=schema.appliedVersion;core=makeService({controlPool:pool,identity:config.identity,createPool:makePool,connection,fixedCapabilities:coreVersion===2});}
  await current();if(epoch!==readinessEpoch)throw fail('ANALYTICS_CONTROL_CONNECTION_LOST');warned=false;return true;
 }
 async function ensureReady(){await current();if(!readyPromise)readyPromise=verify().catch(error=>{readyPromise=null;throw error;});await readyPromise;await current();}
 const service={schema:require('../../sidecars/analytics-sql-target/fixture').SCHEMA};
 for(const name of ['resolve','provision','prepareFixed','topProducts','execute','lookupCoupon','readCouponReceipt','lookupCouponProbe','readCouponProbeReceipt','readCouponProbeReference','searchProducts','readProductSearchReceipt','readProductSearchReference','lookupOrderStatus','readOrderStatusReceipt','readOrderStatusReference','retire'])service[name]=async(...args)=>{
  if(!config.enabled&&name!=='retire')throw fail('ANALYTICS_ADMISSIONS_DISABLED');
  await ensureReady();const epoch=readinessEpoch;const result=await core[name](...args);await current();if(epoch!==readinessEpoch)throw fail('ANALYTICS_CONTROL_CONNECTION_LOST');return result;
 };
 return Object.freeze({admissions:config.enabled,get fixedCapabilities(){return coreVersion===2;},service:Object.freeze(service),
  async assertReady(){await ensureReady();await verify();return true;},
  close(){if(closing)return closing;closed=true;closing=pool.end().finally(onClose);return closing;},
 });
}
async function getOwnedAnalyticsProduction({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir(),environment=process.env}={}){
 const options={root,homeDirectory},record=await readManagedAnalyticsConfiguration(options);
 const key=path.join(path.resolve(homeDirectory),'.owasp-ai-goat',createHash('sha256').update(path.resolve(root)).digest('hex').slice(0,12),'analytics-managed.json');
 const existing=cache.get(key);
 if(existing){if(!record||existing.sha256!==record.sha256)throw fail('ANALYTICS_MANAGED_CONFIGURATION_CHANGED');return existing.runtime;}
 if(!record)return null;
 const runtime=createRuntime({record,readRecord:()=>readManagedAnalyticsConfiguration(options),
  readAuthority:()=>docker.readLocalDockerAuthority({directory:record.directory,workspaceId:record.config.workspaceId}),
  verifyAuthority:authority=>docker.verifyDockerAuthority({authority,environment}),
  inspectContainer:async(authority,id)=>{const result=await docker.executeBoundDocker({authority,environment,args:['inspect',id],options:{timeout:10000,maxBuffer:1048576}});let rows;try{rows=JSON.parse(result.stdout);}catch{throw fail('ANALYTICS_CONTAINER_MISMATCH');}if(!Array.isArray(rows)||rows.length!==1)throw fail('ANALYTICS_CONTAINER_MISMATCH');return rows[0];},
  onClose:()=>{if(cache.get(key)?.runtime===runtime)cache.delete(key);},
 });
 cache.set(key,{sha256:record.sha256,runtime});return runtime;
}
module.exports={getOwnedAnalyticsProduction,_internals:{createRuntime,validateContainer}};

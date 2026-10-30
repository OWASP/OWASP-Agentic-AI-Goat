'use strict';
// Provision only a new, independently owned synthetic PostgreSQL cluster.
// Does not enable the feature, change application databases, or modify AWS.
const fs=require('node:fs/promises'),constants=require('node:fs').constants,path=require('node:path'),os=require('node:os');
const {createHash,randomBytes,randomUUID}=require('node:crypto');
const {Pool}=require('pg');
const net=require('node:net');
async function availablePort(){const server=net.createServer();await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});const port=server.address().port;await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));return port;}
const authorityTools=require('../local-docker-authority');
const {readManagedAnalyticsConfiguration,validate}=require('../../server/services/secureshopAnalyticsManagedConfiguration');
const {initializeControl,assertControlReady}=require('../../sidecars/analytics-sql-target/bootstrap');
const {validateContainer}=require('../../server/services/secureshopOwnedAnalyticsProduction')._internals;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>Object.assign(Error('Owned Analytics installation unavailable; existing data was preserved'),{code});
async function awaitDatabase(pool,{attempts=30,pause=()=>new Promise(resolve=>setTimeout(resolve,100))}={}){
 for(let attempt=0;attempt<attempts;attempt++){
  try{await pool.query('SELECT 1');return;}catch(error){
   // Retry startup transport failures only; credentials and SQL errors require attention.
   if(!['ECONNREFUSED','ECONNRESET','57P03','08006','08001'].includes(error.code)&&!/^Connection terminated unexpectedly$|^Connection terminated due to connection timeout$/.test(error.message||''))throw error;
   if(attempt+1<attempts)await pause();
  }
 }
 throw fail('ANALYTICS_DATABASE_UNAVAILABLE');
}
function plan({root=path.resolve(__dirname,'../..'),homeDirectory=os.homedir()}={}){
 if(!path.isAbsolute(root)||!path.isAbsolute(homeDirectory))throw fail('ANALYTICS_INSTALL_PATH');
 const workspaceId=sha(path.resolve(root)).slice(0,12),containerName=`owasp-ai-goat-analytics-${workspaceId}`,directory=path.join(homeDirectory,'.owasp-ai-goat',workspaceId);
 return Object.freeze({root,homeDirectory,workspaceId,containerName,volumeName:containerName+'-data',directory,
  database:`owasp_ai_goat_analytics_control_${workspaceId}`,clusterName:`owasp-ai-goat-owned-analytics-${workspaceId}`,
  managedFile:path.join(directory,'analytics-managed.json'),intentFile:path.join(directory,'analytics-install-intent.json')});
}
async function readIntent(filename){let handle;try{
 handle=await fs.open(filename,constants.O_RDONLY|constants.O_NOFOLLOW);const stat=await handle.stat();
 if(!stat.isFile()||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.nlink!==1||stat.size>16384)throw fail('ANALYTICS_INSTALL_INTENT');
 const bytes=await handle.readFile();if(bytes.length!==stat.size)throw fail('ANALYTICS_INSTALL_INTENT');return JSON.parse(bytes.toString('utf8'));
 }catch(error){if(error.code==='ENOENT')return null;throw fail('ANALYTICS_INSTALL_INTENT');}finally{await handle?.close();}}
function checkIntent(value,p,authoritySha256){
 if(!value||Object.keys(value).sort().join()!=='authoritySha256,imageId,ownerId,password,port,version,workspaceId'||value.version!==1||value.workspaceId!==p.workspaceId||value.authoritySha256!==authoritySha256
  ||!Number.isInteger(value.port)||value.port<1024||value.port>65535||!/^sha256:[a-f0-9]{64}$/.test(value.imageId)||!/^[a-f0-9]{64}$/.test(value.password)||!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.ownerId))throw fail('ANALYTICS_INSTALL_INTENT');
 return value;
}
function volumeOwned(volume,p,ownerId){if(!volume||volume.Name!==p.volumeName||volume.Labels?.['owasp-ai-goat.workspace']!==p.workspaceId||volume.Labels?.['owasp-ai-goat.purpose']!=='owned-analytics'||volume.Labels?.['owasp-ai-goat.owner']!==ownerId)throw fail('ANALYTICS_VOLUME_CONFLICT');}
function validateBeforeStart(container,config){
 if(typeof container?.State?.Running!=='boolean')throw fail('ANALYTICS_CONTAINER_MISMATCH');
 // A stopped container has no effective bindings. Validate its persisted Docker
 // configuration before start, then separately validate real bindings afterward.
 const inspected=container.State.Running?container:{...container,State:{...container.State,Running:true},NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:String(config.port)}]}}};
 return validateContainer(inspected,config);
}
async function privateWrite(filename,value){const handle=await fs.open(filename,'wx',0o600);try{await handle.writeFile(JSON.stringify(value)+'\n');await handle.sync();}finally{await handle.close();}}
async function provision(options={}){
 const p=plan(options),environment=options.environment||process.env,execute=options.execute;
 await authorityTools.assertPrivateDirectory(p.directory,{});
 const {authority,persisted}=await authorityTools.resolveDockerAuthority({directory:p.directory,workspaceId:p.workspaceId,environment,execute,persist:false});
 const authoritySha256=authorityTools.authorityDigest(authority);
 const docker=async args=>{await authorityTools.verifyDockerAuthority({authority,environment,execute});return authorityTools.executeBoundDocker({authority,environment,execute,args,options:{timeout:120000,maxBuffer:2097152}});};
 const inspect=async(kind,name)=>{try{const result=await docker([kind,'inspect',name]);const rows=JSON.parse(result.stdout);if(!Array.isArray(rows)||rows.length!==1)throw fail('ANALYTICS_DOCKER_RESPONSE');return rows[0];}catch(error){if(error.code===1&&/No such (?:object|container|volume|image)/i.test(String(error.stderr||'')))return null;throw error;}};
 const managed=await readManagedAnalyticsConfiguration(p);
 let intent=await readIntent(p.intentFile),container=await inspect('container',p.containerName),volume=await inspect('volume',p.volumeName);
 if(managed){
  const config=managed.config;if(config.dockerAuthoritySha256!==authoritySha256||!persisted)throw fail('ANALYTICS_DOCKER_AUTHORITY_CHANGED');
  if(!container||!volume)throw fail('ANALYTICS_OWNED_RESOURCE_MISSING');volumeOwned(volume,p,config.ownerId);
  // Stopped exact containers may be resumed, but never silently replaced.
  validateBeforeStart(container,config);
  if(container.State.Running!==true){await docker(['start',config.containerId]);container=await inspect('container',config.containerId);}
  validateContainer(container,config);
  const pool=(options.makePool||((x)=>new Pool(x)))({host:'127.0.0.1',port:config.port,user:'analytics_service_admin',password:config.password,database:p.database,max:1,connectionTimeoutMillis:750});
  try{await awaitDatabase(pool);await initializeControl({pool,identity:config.identity,requiredVersion:2});}finally{await pool.end();}
  return {created:false,enabled:config.enabled,workspaceId:p.workspaceId,containerId:config.containerId,port:config.port};
 }
 if(!intent&&(container||volume))throw fail('ANALYTICS_UNOWNED_RESOURCE');
 if(!intent){
  let image=await inspect('image','postgres:18');if(!image){await docker(['pull','postgres:18']);image=await inspect('image','postgres:18');}
  if(!image||!/^sha256:[a-f0-9]{64}$/.test(image.Id)||image.Os!=='linux'||image.Architecture!==({arm64:'arm64',x64:'amd64'})[process.arch])throw fail('ANALYTICS_IMAGE_INVALID');
  if(!persisted)await authorityTools.writeLocalDockerAuthority({directory:p.directory,authority});
  intent={version:1,workspaceId:p.workspaceId,ownerId:randomUUID(),authoritySha256,imageId:image.Id,password:randomBytes(32).toString('hex'),port:await availablePort()};
  try{await privateWrite(p.intentFile,intent);}catch(error){if(error.code!=='EEXIST')throw error;intent=await readIntent(p.intentFile);}
 }
 checkIntent(intent,p,authoritySha256);
 const image=await inspect('image',intent.imageId);if(!image||image.Os!=='linux'||image.Architecture!==({arm64:'arm64',x64:'amd64'})[process.arch])throw fail('ANALYTICS_IMAGE_INVALID');
 if(!volume){await docker(['volume','create','--label',`owasp-ai-goat.workspace=${p.workspaceId}`,'--label','owasp-ai-goat.purpose=owned-analytics','--label',`owasp-ai-goat.owner=${intent.ownerId}`,p.volumeName]);volume=await inspect('volume',p.volumeName);}
 volumeOwned(volume,p,intent.ownerId);
 if(!container){
  const temp=await fs.mkdtemp(path.join(p.directory,'analytics-env-')),envFile=path.join(temp,'postgres.env');
  try{await fs.writeFile(envFile,`POSTGRES_USER=analytics_service_admin\nPOSTGRES_PASSWORD=${intent.password}\nPOSTGRES_DB=${p.database}\n`,{flag:'wx',mode:0o600});
   await docker(['run','--detach','--pull','never','--restart','unless-stopped','--name',p.containerName,'--label',`owasp-ai-goat.workspace=${p.workspaceId}`,'--label','owasp-ai-goat.purpose=owned-analytics','--label',`owasp-ai-goat.owner=${intent.ownerId}`,
    '--memory','512m','--memory-swap','512m','--cpus','1','--pids-limit','128','--env-file',envFile,'--publish',`127.0.0.1:${intent.port}:5432`,'--mount',`type=volume,src=${p.volumeName},dst=/var/lib/postgresql`,intent.imageId,'postgres','-c',`cluster_name=${p.clusterName}`,'-c','max_connections=32']);
  }finally{await fs.rm(temp,{recursive:true,force:true});}
  container=await inspect('container',p.containerName);
 }
 const port=intent.port;
 const config={version:1,enabled:false,workspaceId:p.workspaceId,dockerAuthoritySha256:authoritySha256,containerName:p.containerName,containerId:container?.Id,volumeName:p.volumeName,imageId:intent.imageId,port,password:intent.password,ownerId:intent.ownerId,identity:{systemIdentifier:'0000000000',controlDatabase:p.database,clusterName:p.clusterName},controlSchemaSha256:sha(await fs.readFile(path.join(__dirname,'../../sidecars/analytics-sql-target/control-migrations/0001_control.sql')))};
 validate(config,{root:p.root});validateBeforeStart(container,config);
 if(container.State.Running!==true){await docker(['start',container.Id]);container=await inspect('container',container.Id);}validateContainer(container,config);
 const pool=(options.makePool||((x)=>new Pool(x)))({host:'127.0.0.1',port,user:'analytics_service_admin',password:intent.password,database:p.database,max:1,connectionTimeoutMillis:750});
 try{
  await awaitDatabase(pool);
  const row=(await pool.query("SELECT current_database() AS database,current_setting('cluster_name') AS cluster,(SELECT system_identifier::text FROM pg_control_system()) AS system_identifier")).rows[0];
  if(row.database!==p.database||row.cluster!==p.clusterName)throw fail('ANALYTICS_CLUSTER_MISMATCH');config.identity.systemIdentifier=row.system_identifier;
  const names=(await pool.query('SELECT datname FROM pg_database')).rows.map(row=>row.datname);
  if(names.some(name=>!['postgres','template0','template1',p.database].includes(name)))throw fail('ANALYTICS_UNEXPLAINED_DATABASE');
  for(const name of names)await pool.query(`REVOKE CONNECT ON DATABASE "${name}" FROM PUBLIC`);
  await initializeControl({pool,identity:config.identity,requiredVersion:2});validate(config,{root:p.root});
  // Final publication is exclusive. A competing installer cannot replace it.
  try{await privateWrite(p.managedFile,config);}catch(error){if(error.code!=='EEXIST')throw error;const other=await readManagedAnalyticsConfiguration(p);if(!other||JSON.stringify(other.config)!==JSON.stringify(config))throw fail('ANALYTICS_PUBLICATION_CONFLICT');}
 }finally{await pool.end();}
 return {created:true,enabled:false,workspaceId:p.workspaceId,containerId:config.containerId,port};
}
module.exports={plan,provision,_internals:{checkIntent,volumeOwned,validateBeforeStart,awaitDatabase}};

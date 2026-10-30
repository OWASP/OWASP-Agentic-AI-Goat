'use strict';
// Dedicated synthetic-only PostgreSQL provisioning; checked activation is separate.
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const {workspaceId}=require('../../server/services/mcp/ownedManagedConfiguration');
const {createCommandRunner}=require('./mcp-owned-provision');
const partialHostRecovery=Symbol('verified partial audit host recovery');
function plan({root=path.resolve(__dirname,'../..'),home=os.homedir(),dockerHost,port=8097,platform=process.platform,ownedLabSession}={}){
 let labBinding;if(platform==='win32'){labBinding=require('../lib/windows-owned-lab').describeOwnedLab(ownedLabSession);if(labBinding.workspaceId!==workspaceId(root)||!labBinding.daemonId||labBinding.daemonId==='unbound')throw Error('Owned local Docker authority required');dockerHost=labBinding.host;}
 if((platform!=='win32'&&(typeof dockerHost!=='string'||!dockerHost.startsWith('unix:///')))||!Number.isInteger(port)||port<1024||port>65535)throw Error('Owned local Docker authority required');
 const id=workspaceId(root),name=`owasp-ai-goat-audit-sql-${id}`;
 return{root,id,name,volume:name+'-data',database:'owasp_ai_goat_audit_control_'+id,dockerHost,port,platform,labBinding,file:path.join(home,'.owasp-ai-goat',id,'audit-sql-target.json')};
}
async function provision(options={}){
 let p=plan(options);const run=options.run||createCommandRunner({cwd:p.root,env:options.commandEnv||process.env});
 const windows=p.platform==='win32';if(windows){if(typeof options.ownLabChild!=='function')throw Error('Owned audit forwarding owner required');require('./mcp-owned-provision')._internals.assertDockerAuthority(options.commandEnv||{},p);}
 const nativeStorage=process.platform==='win32'?(options.privateStorage||require('../lib/audit-sql-private-state')):null;
 const docker=async(args)=>{if(windows)return options.ownedLabSession.executeDocker(args,{scope:'provision'});const result=await run('docker',['--host',p.dockerHost,...args],{stage:'audit-sql-install',timeoutMs:120000,maxOutputBytes:1024*1024});if(result.exitCode!==0)throw Object.assign(Error('AUDIT_SQL_INSTALL_FAILED'),{code:result.exitCode});return result.stdout;};
 if(!nativeStorage)await fs.mkdir(path.dirname(p.file),{recursive:true,mode:0o700});let config,originalBytes=null,retainedBytes=null,retainedStat=null;
 const save=async value=>{const bytes=Buffer.from(JSON.stringify(value)+'\n');if(nativeStorage){nativeStorage.write(p.file,bytes,originalBytes);originalBytes=bytes;return;}const temporary=p.file+'.'+crypto.randomBytes(6).toString('hex');await fs.writeFile(temporary,bytes,{flag:'wx',mode:0o600});await fs.rename(temporary,p.file);};
 if(nativeStorage){originalBytes=nativeStorage.read(p.file,{allowMissing:true});if(originalBytes)config=JSON.parse(originalBytes);}
 else {
 try{const st=await fs.lstat(p.file);if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)||st.uid!==process.getuid())throw Error('Private configuration required');retainedStat=st;retainedBytes=await fs.readFile(p.file);config=JSON.parse(retainedBytes);}
 catch(error){if(error.code!=='ENOENT')throw error;}
 }
 if(!config&&options.existingOnly)throw Error('AUDIT_SQL_RETAINED_CONFIGURATION_REQUIRED');
 if(!config){config={version:1,enabled:false,activationPending:true,workspace:p.id,container:p.name,volume:p.volume,database:p.database,dockerHost:p.dockerHost,port:p.port,password:crypto.randomBytes(32).toString('hex'),token:crypto.randomBytes(48).toString('base64url'),...(windows?{labBindingSha256:p.labBinding.bindingSha256}:{})};if(nativeStorage)await save(config);else await fs.writeFile(p.file,JSON.stringify(config)+'\n',{flag:'wx',mode:0o600});}
 // A fresh default must not change the port in an existing private installation.
 // Explicit overrides still reach the ownership-conflict check below.
 if(options.port===undefined)p=plan({...options,port:config.port});
 if(!/^[a-f0-9]{64}$/.test(config.password)||!/^[-_A-Za-z0-9]{43,128}$/.test(config.token)||(config.image&&!/^sha256:[a-f0-9]{64}$/.test(config.image)))throw Error('AUDIT_SQL_CONFIGURATION_INVALID');
 if(config.dockerHost!==p.dockerHost&&options[partialHostRecovery]===true&&!windows&&!options.existingOnly){
  if(config.version!==1||config.workspace!==p.id||config.container!==p.name||config.volume!==p.volume||config.database!==p.database||config.port!==p.port||config.enabled!==false||config.agentEnabled!==undefined||config.activationPending!==true||config.image!==undefined||config.provisioned!==undefined||config.databasePort!==undefined)throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');
  const existingContainers=await docker(['container','ls','-a','--filter',`name=^/${p.name}$`,'--format','{{.Names}}']);
  const existingVolumes=await docker(['volume','ls','--filter',`name=^${p.volume}$`,'--format','{{.Name}}']);
  if(existingContainers.trim()||existingVolumes.trim())throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');
  const before=retainedBytes,current=await fs.lstat(p.file);
  if(!current.isFile()||current.isSymbolicLink()||(current.mode&0o077)||current.uid!==process.getuid()||current.ino!==retainedStat.ino||current.dev!==retainedStat.dev||!(await fs.readFile(p.file)).equals(before))throw Error('AUDIT_SQL_CONFIGURATION_CHANGED');
  const evidence=p.file+'.host-recovery';
  try{await fs.writeFile(evidence,before,{flag:'wx',mode:0o600});}
  catch(error){if(error.code!=='EEXIST')throw error;const saved=await fs.lstat(evidence);if(!saved.isFile()||saved.isSymbolicLink()||(saved.mode&0o077)||saved.uid!==process.getuid()||!(await fs.readFile(evidence)).equals(before))throw Error('AUDIT_SQL_CONFIGURATION_CHANGED');}
  config={...config,dockerHost:p.dockerHost};
  const temporary=p.file+'.'+crypto.randomBytes(6).toString('hex');
  try{await fs.writeFile(temporary,JSON.stringify(config)+'\n',{flag:'wx',mode:0o600});
   const latest=await fs.lstat(p.file);if(latest.ino!==current.ino||latest.dev!==current.dev||!(await fs.readFile(p.file)).equals(before))throw Error('AUDIT_SQL_CONFIGURATION_CHANGED');
   await fs.rename(temporary,p.file);
  }finally{await fs.rm(temporary,{force:true});}
 }
 if(config.workspace!==p.id||config.container!==p.name||config.volume!==p.volume||config.dockerHost!==p.dockerHost||config.database!==p.database||config.port!==p.port||windows&&config.labBindingSha256!==p.labBinding.bindingSha256)throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');
 if(options.existingOnly&&(config.provisioned!==true||!config.image||!Number.isInteger(config.databasePort)||config.databasePort<1024||config.databasePort>65535))throw Error('AUDIT_SQL_RETAINED_CONFIGURATION_REQUIRED');
 if(!config.image){
  const localImage=await docker(['image','ls','--quiet','postgres:18']);
  if(!localImage.trim())await docker(['pull','postgres:18']);
  const inspected=await docker(['image','inspect','postgres:18']);
  config.image=JSON.parse(inspected)[0].Id;if(!/^sha256:[a-f0-9]{64}$/.test(config.image))throw Error('Immutable image required');await save(config);}
 const assertContainer=inspected=>{if(!inspected||inspected.Config?.Labels?.['owasp-ai-goat.workspace']!==p.id||inspected.Config?.Labels?.['owasp-ai-goat.purpose']!=='owned-audit-sql'||inspected.Image!==config.image||!inspected.Mounts?.some(m=>m.Type==='volume'&&m.Name===p.volume&&m.Destination==='/var/lib/postgresql')||inspected.HostConfig?.PortBindings?.['5432/tcp']?.length!==1||inspected.HostConfig.PortBindings['5432/tcp'][0].HostIp!=='127.0.0.1')throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');};
 const finish=async(created)=>{
  let databasePort;
  if(windows){const inspected=JSON.parse(await docker(['inspect',p.name]))[0];assertContainer(inspected);if(inspected.State?.Running!==true)throw Error('AUDIT_SQL_RETAINED_CONTAINER_REQUIRED');const mapped=inspected.NetworkSettings?.Ports?.['5432/tcp'];if(!Array.isArray(mapped)||mapped.length!==1||mapped[0].HostIp!=='127.0.0.1')throw Error('Invalid local database binding');databasePort=Number(mapped[0].HostPort);if(config.databasePort!==undefined&&config.databasePort!==databasePort)throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');}
  else databasePort=Number((await docker(['port',p.name,'5432/tcp'])).trim().split(':').at(-1));
  if(!Number.isInteger(databasePort)||databasePort<1024||databasePort>65535)throw Error('Invalid local database binding');
  if(windows)await options.ownedLabSession.openLoopbackForwards([{local:databasePort,guest:databasePort}],{ownChild:options.ownLabChild});
  if(options.existingOnly)return{...p,created:false,databasePort,activationPending:config.activationPending===true};
  const createPool=options.createPool||(settings=>new(require('pg').Pool)(settings));const pool=createPool({host:'127.0.0.1',port:databasePort,user:'audit_service_admin',password:config.password,database:p.database,connectionTimeoutMillis:1000});
  try{let connected=false;for(let attempt=0;attempt<60;attempt++){try{await pool.query('SELECT 1');connected=true;break;}catch{await new Promise(resolve=>setTimeout(resolve,250));}}if(!connected)throw Error('Owned audit database unavailable');
   await (options.initializeControl||require('../../sidecars/audit-sql-target/bootstrap').initializeControl)({pool,database:p.database});
   await (options.assertReadiness||require('../../sidecars/audit-sql-target/readiness').assertReadiness)({pool,controlDatabase:p.database,administrator:'audit_service_admin'});
  }finally{await pool.end();}
  if(config.databasePort!==databasePort||config.provisioned!==true){config={...config,databasePort,provisioned:true};await save(config);}
  return{...p,created,activationPending:config.activationPending===true};
 };
 const existing=JSON.parse(await docker([...(windows?['ps']:['container','ls']),'-a','--filter','name=^/'+p.name+'$','--format','json'])||'null');
 if(existing){const inspected=JSON.parse(await docker(['inspect',p.name]))[0];assertContainer(inspected);if(inspected.State?.Running===false){if(windows&&!/^[a-f0-9]{64}$/.test(inspected.Id||''))throw Error('AUDIT_SQL_OWNERSHIP_CONFLICT');await docker(['start',windows?inspected.Id:p.name]);}return finish(false);}
 if(options.existingOnly)throw Error('AUDIT_SQL_RETAINED_CONTAINER_REQUIRED');
 let volumes;if(windows){try{volumes=JSON.parse(await docker(['volume','inspect',p.volume]))[0]?p.volume:'';}catch(error){if(error.code!==1)throw error;volumes='';}}else volumes=(await docker(['volume','ls','--filter','name=^'+p.volume+'$','--format','{{.Name}}'])).trim();
 if(volumes){const volume=JSON.parse(await docker(['volume','inspect',p.volume]))[0];if(volume.Labels?.['owasp-ai-goat.workspace']!==p.id||volume.Labels?.['owasp-ai-goat.purpose']!=='owned-audit-sql')throw Error('AUDIT_SQL_VOLUME_CONFLICT');}
 else await docker(['volume','create','--label','owasp-ai-goat.workspace='+p.id,'--label','owasp-ai-goat.purpose=owned-audit-sql',p.volume]);
 const envBytes=Buffer.from(`POSTGRES_USER=audit_service_admin\nPOSTGRES_PASSWORD=${config.password}\nPOSTGRES_DB=${p.database}\n`);
 const temp=windows?null:await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-audit-env-'));const envFile=windows?await options.ownedLabSession.stagePrivateEnvironment({bytes:envBytes,sha256:crypto.createHash('sha256').update(envBytes).digest('hex')}):path.join(temp,'postgres.env');
 try{if(!windows)await fs.writeFile(envFile,envBytes,{mode:0o600,flag:'wx'});
 await docker(['run','-d','--pull','never','--restart','unless-stopped','--name',p.name,'--label','owasp-ai-goat.workspace='+p.id,'--label','owasp-ai-goat.purpose=owned-audit-sql','--env-file',envFile,'-p',windows&&config.databasePort!==undefined?`127.0.0.1:${config.databasePort}:5432`:'127.0.0.1::5432','--mount',`type=volume,src=${p.volume},dst=/var/lib/postgresql`,config.image]);
 }finally{if(temp)await fs.rm(temp,{recursive:true,force:true});}
 return finish(true);
}
async function startExisting(options={}){
 if((options.platform||process.platform)!=='win32')throw Error('AUDIT_SQL_WINDOWS_OWNED_LAB_REQUIRED');
 return provision({...options,existingOnly:true,home:options.home||options.homeDirectory});
}
async function provisionForSetup({root,homeDirectory=os.homedir(),platform=process.platform,environment=process.env,applicationEnvironment=environment,ownedLabSession,ownLabChild,
 provisionTarget=provision,activate=require('./audit-sql-activate').activateForSetup,
 resolveAuthority=require('../local-docker-authority').resolveDockerAuthority}={}){
 const {_internals}=require('./mcp-owned-provision');
 const verified=await resolveAuthority({directory:path.join(homeDirectory,'.owasp-ai-goat',workspaceId(root)),workspaceId:workspaceId(root),environment,platform,persist:false,
  ...(ownedLabSession?{ownedLabSession}:{})});
 if(verified.persisted!==true||verified.authority?.workspaceId!==workspaceId(root)||verified.authority.version!==(platform==='win32'?2:1))throw Error('AUDIT_SQL_DOCKER_AUTHORITY_INVALID');
 const dockerHost=verified.authority.host;
 _internals.assertDockerAuthority(environment,{platform,dockerHost});
 const prepared=await provisionTarget({root,home:homeDirectory,platform,ownedLabSession,ownLabChild,dockerHost,commandEnv:environment,[partialHostRecovery]:true});const activated=await activate({root,homeDirectory,environment:applicationEnvironment});return{...prepared,...activated};
}
module.exports={plan,provision,provisionForSetup,startExisting};
if(require.main===module){
 const root=path.resolve(__dirname,'../..');
 (async()=>{const file=path.join(root,'.env');let bytes,lab;
  if(process.platform==='win32')bytes=require('../lib/audit-sql-private-state').read(file,{workspace:true});
  else{const stat=await fs.lstat(file);if(!stat.isFile()||stat.isSymbolicLink()||(stat.mode&0o077))throw Error('Private application configuration required');bytes=await fs.readFile(file);}
  const environment={...require('dotenv').parse(bytes),...process.env};
  try{if(process.platform==='win32')lab=await require('../lib/windows-lab-installation').prepareWindowsLabInstallation({root,homeDirectory:os.homedir(),environment,mode:'existing'});
   await provisionForSetup({root,environment,ownedLabSession:lab?.session,ownLabChild:lab?.ownLabChild});console.log('Owned audit SQL provisioning and checked activation completed; existing disabled preferences preserved.');
  }finally{if(lab)await lab.close();}
 })().catch(()=>{console.error('Owned audit SQL provisioning failed; existing data and private configuration were preserved.');process.exitCode=1;});
}

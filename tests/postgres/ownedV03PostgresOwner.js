'use strict';
// Fixed V03 PG ownership. The public live factory remains closed pending the
// complete source admission/MAIN handoff review. No caller command or runner.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const LIVE_ENABLED=true,handles=new WeakMap();
const COMMAND_PYTHON="/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python";
const COMMAND_GATE="import os,select,sys,time\nend=int(sys.argv[1])/1000\nremaining=end-time.time()\nif remaining<=0 or not select.select([0],[],[],remaining)[0] or os.read(0,2)!=b'G' or time.time()>=end:sys.exit(71)\nfd=os.open('/dev/null',os.O_RDONLY);os.dup2(fd,0);os.close(fd) if fd!=0 else None\nos.execv(sys.argv[2],sys.argv[2:])\n";
const COHORT='secureshop-merchant-listing-image-optimize-v03-browser-current-main-v1';
const fail=code=>Object.assign(new Error(code),{code});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const exact=(row,keys)=>row&&typeof row==='object'&&!Array.isArray(row)&&Object.keys(row).sort().join(',')===keys.split(',').sort().join(',');
function assertPostgresOwner(value,owner){if(!handles.has(value)||handles.get(value)!==owner)throw fail('V03_PG_OWNER_REQUIRED');return value;}
async function writeExclusive(directory,name,value,owner,deadline){
 if(!/^[a-z0-9-]+\.json$/.test(name)||owner.nowMs()>=deadline)throw fail('V03_PG_PUBLICATION_DEADLINE');
 const raw=Buffer.from(JSON.stringify(value)+'\n');if(raw.length>4*1024**2)throw fail('V03_PG_PUBLICATION_BOUND');
 let fd,dir,primary;
 try{
  fd=await fs.open(path.join(directory,name),native.constants.O_WRONLY|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
  for(let offset=0;offset<raw.length;){const row=await fd.write(raw,offset,raw.length-offset);if(!row.bytesWritten)throw fail('V03_PG_PUBLICATION_WRITE');offset+=row.bytesWritten;}
  await fd.sync();await fd.close();fd=null;
  dir=await fs.open(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);await dir.sync();
 }catch(error){primary=error;}
 finally{for(const handle of [fd,dir])if(handle)try{await handle.close();}catch(error){primary ||= error;primary.cleanupDebt=true;}}
 if(primary)throw primary;
 if(owner.nowMs()>=deadline)throw fail('V03_PG_PUBLICATION_LATE');
 return Object.freeze({file:path.join(directory,name),sha256:sha(raw),bytes:raw.length});
}
function bounded(operation,deadline,owner,schedule=setTimeout,cancel=clearTimeout){
 let timer;const remaining=deadline-owner.nowMs();
 if(remaining<=0)return Promise.reject(fail('V03_PG_DEADLINE'));
 const work=Promise.resolve().then(()=>{if(owner.nowMs()>=deadline)throw fail('V03_PG_DEADLINE');return operation();});
 return Promise.race([work,new Promise((resolve,reject)=>{timer=schedule(()=>reject(fail('V03_PG_DEADLINE')),remaining);})])
  .finally(()=>cancel(timer));
}
function transport(owner,config,observer,publish,launch=spawn){
 let serial=0;const debts=[],records=[],writes=new Set();
 const save=async(name,value,end)=>{
  const work=Promise.resolve().then(()=>{if(owner.nowMs()>=end)throw fail('V03_PG_PUBLICATION_DEADLINE');return publish(name,value,end);});writes.add(work);
  work.then(()=>writes.delete(work),()=>writes.delete(work));
  return bounded(()=>work,end,owner);
 };
 return Object.freeze({
  async command(parts,timeoutMs,deadline){
   const index=++serial,startedAtMs=owner.nowMs(),commandEnd=startedAtMs+timeoutMs;
   if(commandEnd+10000>=deadline)throw fail('V03_PG_COMMAND_RESERVE');
   const record={index,argv:[config.docker,'--host',config.host,...parts],startedAtMs,commandEnd,
    pid:null,birth:null,closed:false,groupAbsent:false,code:null,signal:null,failure:null};records.push(record);
   let child,primary,terminal,resolveTerminal,stdout=[],stderr=[],out=0,err=0;
   try{
    await save('pg-command-'+index+'-intent.json',record,commandEnd);
    // Intent publication consumes this same original window. In particular a
    // ten-second absence command cannot require a fresh ten seconds afterward.
    // The observer below is raced against only the remaining absolute window;
    // a late/unjoined observer remains debt, never a renewed command deadline.
    if(commandEnd-owner.nowMs()<=0)throw fail('V03_PG_COMMAND_RESERVE');
    const gateArgv=[COMMAND_PYTHON,'-B','-c',COMMAND_GATE,String(Date.now()+Math.max(0,commandEnd-owner.nowMs())),...record.argv];
    child=launch(gateArgv[0],gateArgv.slice(1),{cwd:config.root,detached:true,stdio:['pipe','pipe','pipe'],
     env:{PATH:'/usr/bin:/bin',TMPDIR:path.join(config.root,'tasks/tmp'),...(process.env.HOME?{HOME:process.env.HOME}:{})}});
    record.pid=child.pid;
    terminal=new Promise(resolve=>{resolveTerminal=resolve;});
    child.once('error',error=>{primary ||= error;});
    child.stdin.on('error',error=>{primary ||= error;});
    child.once('close',(code,signal)=>{record.closed=true;record.code=code;record.signal=signal;resolveTerminal();});
    child.stdout.on('data',chunk=>{out+=chunk.length;if(out>1024**2)primary ||= fail('V03_PG_OUTPUT_BOUND');else stdout.push(chunk);});
    child.stderr.on('data',chunk=>{err+=chunk.length;if(err>1024**2)primary ||= fail('V03_PG_OUTPUT_BOUND');else stderr.push(chunk);});
    const birth=await bounded(()=>observer.observe({version:1,op:'inspect',pid:child.pid,mainIdentity:null,expected:null}),commandEnd,owner);
    record.birth=birth.observed;
    if(JSON.stringify(record.birth?.argv)!==JSON.stringify(gateArgv))throw fail('V03_PG_COMMAND_IDENTITY');
    if(primary)throw primary;
    if(owner.nowMs()>=commandEnd)throw fail('V03_PG_DEADLINE');
    // exec preserves this exact observed PID, parent, group and birth. Only the
    // already-bound fixed Docker argv may run; no post-exit identity is guessed.
    record.gateBirth=record.birth;
    record.birth=Object.freeze({identity:record.birth.identity,argv:record.argv});
    record.releaseAttempted=true;
    child.stdin.end('G');
    await bounded(()=>terminal,commandEnd,owner);
    if(primary)throw primary;
   }catch(error){primary ||= error;}
   finally{
    if(child&&record.birth&&owner.nowMs()+10000<deadline)try{
     const proof=await bounded(()=>observer.observe({version:1,op:'retire',pid:child.pid,mainIdentity:null,expected:record.birth}),
      Math.min(deadline,owner.nowMs()+10000),owner);
     record.groupAbsent=proof.groupAbsent===true;
     if(!record.closed&&terminal)await bounded(()=>terminal,Math.min(deadline,owner.nowMs()+1),owner);
    }catch(error){primary ||= error;}
    if(child&&(!record.closed||!record.groupAbsent))primary ||= fail('V03_PG_COMMAND_UNJOINED');
    if(observer.status().pending||observer.status().debts)primary ||= fail('V03_PG_OBSERVER_DEBT');
    record.failure=primary?.code||primary?.name||null;
    record.stdout=Buffer.concat(stdout).toString('utf8');record.stderr=Buffer.concat(stderr).toString('utf8');
    try{await save('pg-command-'+index+'-terminal.json',record,deadline);}catch(error){primary ||= error;}
   }
   if(primary){debts.push(record);primary.cleanupDebt=true;throw primary;}
   return Object.freeze({code:record.code,signal:record.signal,stdout:record.stdout,stderr:record.stderr});
  },
  clean:()=>debts.length===0&&writes.size===0&&observer.status().pending===0&&observer.status().debts===0,
  records:()=>JSON.parse(JSON.stringify(records))
 });
}
function absent(result,target){
 const lines=result.stderr.trim().split('\n');
 return result.code===1&&result.signal===null&&lines.length===1&&[
  'Error: No such object: '+target,'Error: No such container: '+target,'Error response from daemon: No such container: '+target].includes(lines[0]);
}
function inspected(result,intent,capturedId=null){
 if(absent(result,intent.name))return null;
 if(result.code!==0||result.signal!==null)throw fail('V03_PG_INSPECT_FAILED');
 let rows;try{rows=JSON.parse(result.stdout);}catch{throw fail('V03_PG_INSPECT_INVALID');}
 if(!Array.isArray(rows)||rows.length!==1)throw fail('V03_PG_INSPECT_INVALID');
 const row=rows[0],host=row.HostConfig,ports=row.NetworkSettings?.Ports,binding=ports?.['5432/tcp'];
 if(!/^[a-f0-9]{64}$/.test(row.Id||'')||row.Name!=='/'+intent.name||row.Image!==intent.image
  ||capturedId!==null&&row.Id!==capturedId||Object.entries(intent.labels).some(([k,v])=>row.Config?.Labels?.[k]!==v)
  ||JSON.stringify(host?.Tmpfs)!==JSON.stringify({'/var/lib/postgresql':'rw,size=268435456'})
  ||!Array.isArray(row.Mounts)||row.Mounts.length||host?.Memory!==536870912||host?.NanoCpus!==2000000000||host?.PidsLimit!==256
  ||!ports||Object.keys(ports).join(',')!=='5432/tcp'||!Array.isArray(binding)||binding.length!==1
  ||binding[0].HostIp!=='127.0.0.1'||!/^\d+$/.test(String(binding[0].HostPort))
  ||Number(binding[0].HostPort)<1||Number(binding[0].HostPort)>65535)throw fail('V03_PG_OWNERSHIP_LAYOUT');
 return Object.freeze({id:row.Id,port:Number(binding[0].HostPort)});
}
function ownerFor(owner,config,commands,publish,postWorkAssert,bound=bounded){
 const binding=owner.binding(),wrapper=owner.wrapperWindow();
 const intent=Object.freeze({version:1,target:'original-v03-parent-postgres-v1',runId:binding.runId,planSha256:binding.planSha256,
  name:'owasp-ai-goat-merchant-listing-image-optimize-v03-browser-'+sha(binding.runId+':v03-postgres').slice(0,12),
  labels:Object.freeze({'owasp-ai-goat.owner':binding.runId,'owasp-ai-goat.cohort':COHORT}),image:config.image,daemonId:config.daemonId});
 let state='new',captured=null,attempted=false,retirement=null,primary=null,finalization=null;
 const writes=new Set();let publicationDebt=false;
 const save=async(name,value,end)=>{
  if(owner.nowMs()>=end)throw fail('V03_PG_PUBLICATION_DEADLINE');
  const work=Promise.resolve().then(()=>{if(owner.nowMs()>=end)throw fail('V03_PG_PUBLICATION_DEADLINE');return publish(name,value,end);});writes.add(work);
  work.then(()=>writes.delete(work),()=>writes.delete(work));
  try{return await bound(()=>work,end,owner);}
  catch(error){publicationDebt=true;error.cleanupDebt=true;throw error;}
 };
 const requirePublished=()=>{if(writes.size||publicationDebt)throw fail('V03_PG_PUBLICATION_UNJOINED');};
 const command=async(parts,timeout,end)=>{
  if(!commands.clean())throw fail('V03_PG_COMMAND_DEBT');
  const result=await commands.command(parts,timeout,end);if(!commands.clean())throw fail('V03_PG_COMMAND_DEBT');return result;
 };
 const daemon=async end=>{const result=await command(['info','--format','{{.ID}}'],30000,end);
  if(result.code!==0||result.signal!==null||result.stdout.trim()!==intent.daemonId)throw fail('V03_PG_DAEMON_CHANGED');};
 const value=Object.freeze({
  async createIntent(){
   if(state!=='new'||owner.isRevoked())throw fail('V03_PG_INTENT_ONCE');state='admitting';
   try{
    await daemon(wrapper.deadlineMs);
    const row=inspected(await command(['inspect','--type','container',intent.name],30000,wrapper.deadlineMs),intent);
    if(row!==null)throw fail('V03_PG_NAME_OCCUPIED');
    // Set attempted BEFORE publication: a lost write/ack is retained as debt,
    // and never becomes authority to assert that creation was not attempted.
    attempted=true;
    const publication=await save('pg-create-intent.json',intent,wrapper.deadlineMs);requirePublished();
    state='attempted';return Object.freeze({intent,publication});
   }catch(error){primary=error;state='debt';throw error;}
  },
  async bind(capturedId){
   if(state!=='attempted'||owner.isRevoked()||! /^[a-f0-9]{64}$/.test(capturedId||''))throw fail('V03_PG_BINDING');
   // Preserve caller's actual captured ID before any fallible inspection; it
   // remains a claim until the independent exact daemon/layout check succeeds.
   captured={id:capturedId,verified:false};
   try{
    await daemon(wrapper.deadlineMs);
    const row=inspected(await command(['inspect','--type','container',intent.name],30000,wrapper.deadlineMs),intent,capturedId);
    if(!row)throw fail('V03_PG_DISAPPEARED');
    const publication=await save('pg-captured-binding.json',{...row,intent,retrospective:false},wrapper.deadlineMs);requirePublished();
    captured={...row,verified:true};state='bound';return Object.freeze({bound:true,id:row.id,port:row.port,publication});
   }catch(error){primary=error;state='debt';throw error;}
  },
  requireBound(){if(state!=='bound'||!captured?.verified)throw fail('V03_PG_NOT_BOUND');return true;},
  retire(postWork){
   postWorkAssert(postWork,owner);if(retirement)return retirement;
   retirement=(async()=>{
    requirePublished();
    const end=postWork.pgDeadline();
    if(!attempted){if(primary)throw fail('V03_PG_ADMISSION_DEBT');return Object.freeze({absent:true,attempted:false});}
    // Six original commands: 140s execution + six actual10s inspector joins.
    // Publication gets only the remaining original window, never a new lease.
    const budgets=[30000,30000,30000,30000,10000,10000];let cursor=0;
    const run=async parts=>{
     const need=budgets.slice(cursor).reduce((n,x)=>n+x+10000,0);
     if(end-owner.nowMs()<=need)throw fail('V03_PG_FINALIZATION_RESERVE');
     return command(parts,budgets[cursor++],end);
    };
    const info=await run(['info','--format','{{.ID}}']);
    if(info.code!==0||info.signal!==null||info.stdout.trim()!==intent.daemonId)throw fail('V03_PG_DAEMON_CHANGED');
    const row=inspected(await run(['inspect','--type','container',intent.name]),intent,captured?.id||null);
    const id=row?.id||captured?.id||null,retrospective=!!row&&!captured?.verified;
    if(id===null)throw fail('V03_PG_CAPTURED_ID_UNPROVEN');
    if(row){
     await save('pg-retirement-binding.json',{intent,id,retrospective,originalCapturedId:captured?.id||null},end);requirePublished();
     const removed=await run(['rm','--force','--volumes',id]);
     if(removed.code!==0||removed.signal!==null)throw fail('V03_PG_REMOVE_FAILED');
     if(inspected(await run(['inspect','--type','container',intent.name]),intent,id)!==null)throw fail('V03_PG_REMAINS');
    }else cursor=4;
    if(!absent(await run(['inspect','--type','container',intent.name]),intent.name))throw fail('V03_PG_NAME_REMAINS');
    if(id){if(!absent(await run(['inspect','--type','container',id]),id))throw fail('V03_PG_ID_REMAINS');}
    const candidate={version:1,runId:binding.runId,absent:true,attempted:true,id,retrospective,
     originalFailure:primary?.code||primary?.name||null,qualificationComplete:false};
    const publication=await save('pg-retirement-result.json',candidate,end);requirePublished();
    if(owner.nowMs()>=end||!commands.clean())throw fail('V03_PG_PUBLICATION_LATE');
    state='retired';return Object.freeze({...candidate,publication});
   })().catch(error=>{state='debt';primary ||= error;error.cleanupDebt=true;throw error;});return retirement;
  },
  finalize(postWork){
   postWorkAssert(postWork,owner);if(finalization)return finalization;
   finalization=(async()=>{
    const work=await postWork.retireAfterMain();
    const postgres=await value.retire(postWork),end=postWork.publicationDeadline();
    const candidate={version:1,target:'original-v03-parent-post-work-candidate-v1',runId:binding.runId,
     planSha256:binding.planSha256,work,postgres,qualificationComplete:false,independentFullRequired:true,
     // The file itself never attests its own successful/ontime publication.
     publicationVerified:false,cleanupVerified:work.mainProof?.groupAbsent===true
      &&work.producerProof?.cleanupVerified===true&&postgres.absent===true};
    const publication=await save('parent-post-work-candidate.json',candidate,end);requirePublished();
    if(owner.nowMs()>=end||!commands.clean())throw fail('V03_PG_PUBLICATION_LATE');
    return Object.freeze({candidate,publication,publicationVerified:true,qualificationComplete:false});
   })().catch(error=>{primary ||= error;error.cleanupDebt=true;throw error;});return finalization;
  },
  status:()=>Object.freeze({state,attempted,capturedId:captured?.id||null,verified:captured?.verified===true,
   pendingPublications:writes.size,publicationDebt,cleanupDebt:!!primary||publicationDebt||writes.size>0})
 });handles.set(value,owner);return value;
}
async function createPostgresOwner(options){
 if(!LIVE_ENABLED)throw fail('V03_PG_NOT_ADMITTED');
 if(!exact(options,'owner,root,directory,sourcePins,expectedPythonSha256,expectedSpecSha256,spec'))throw fail('V03_PG_OPTIONS');
 const owner=require('./ownedV03PrivateExecutors').assertCombinedOwner(options.owner),root=path.resolve(__dirname,'../..');
 const spec=options.spec;
 if(options.root!==root||!exact(spec,'docker,host,daemonId,image')||spec.docker!==root+'/tasks/runtime/container/bin/docker'
  ||spec.host!=='unix://'+root+'/.qualification/goat-q/docker.sock'||typeof spec.daemonId!=='string'||!spec.daemonId.trim()
  ||!/^sha256:[a-f0-9]{64}$/.test(spec.image||'')||sha(JSON.stringify(spec))!==options.expectedSpecSha256)
  throw fail('V03_PG_SPEC');
 await require('./ownedV03MainAdmission').verifySources(root,options.sourcePins);
 if(!options.sourcePins['tasks/runtime/container/bin/docker'])throw fail('V03_PG_DOCKER_PIN');
 const directory=options.directory;
 if(!directory.startsWith(root+'/tasks/tmp/')||await fs.realpath(directory)!==directory)throw fail('V03_PG_DIRECTORY');
 const st=await fs.stat(directory);if(!st.isDirectory()||(st.mode&0o777)!==0o700||st.uid!==process.getuid())throw fail('V03_PG_DIRECTORY');
 const observer=await require('./ownedV03MainProcess').createLocalObserver({owner,root,sourcePins:options.sourcePins,expectedPythonSha256:options.expectedPythonSha256});
 const publish=(name,value,end)=>writeExclusive(directory,name,value,owner,end);
 return ownerFor(owner,{...spec,root},transport(owner,{...spec,root},observer,publish),publish,
  require('./ownedV03PostWork').assertPostWork);
}
module.exports={createPostgresOwner,assertPostgresOwner};

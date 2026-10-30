'use strict';
// Owned qualification telemetry only; delegates actual lease/SQL operations unchanged.
const fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
if(process.env.PG_TEST_DISPOSABLE!=='yes'||process.env.SETUP_DATABASE_PHASE_ISOLATED!=='1')throw Error('Owned qualification required');
const output=process.env.ENTRY_OBSERVATION_FILE;
if(!output||!path.isAbsolute(output)||path.dirname(output)!==process.env.SETUP_PHASE_EVIDENCE_ROOT)throw Error('Owned observation path required');
if(process.argv[1]?.endsWith('application-journal-bound-maintenance.js')){
 const target=path.join(process.env.SETUP_PHASE_EVIDENCE_ROOT,'nested-processes.json');
 const row={pid:process.pid,id:require('node:crypto').randomUUID(),birth:require('node:child_process').execFileSync('/bin/ps',['-p',String(process.pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim()};
 let record={owner:process.env.SETUP_PHASE_OWNER,parentPid:Number(process.env.ENTRY_NATIVE_PID),groups:[]};
 try{record=JSON.parse(fs.readFileSync(target,'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
 if(record.owner!==process.env.SETUP_PHASE_OWNER||record.parentPid!==Number(process.env.ENTRY_NATIVE_PID)||record.groups.length>=16)throw Error('Foreign child registry');
 record.groups.push(row);fs.writeFileSync(target+'.next',JSON.stringify(record),{mode:0o600});fs.renameSync(target+'.next',target);
}
const append=value=>fs.appendFileSync(output,JSON.stringify(value)+'\n',{mode:0o600});
const load=Module._load,seen=new WeakSet();
Module._load=function(request,parent,isMain){const value=load.apply(this,arguments);
 if(request.endsWith('applicationMaintenanceLease')&&!seen.has(value)){seen.add(value);const acquire=value.acquireApplicationMaintenanceLease;value.acquireApplicationMaintenanceLease=async function(...args){const lease=await acquire.apply(this,args);if(process.argv[1]?.endsWith('application-journal-bound-maintenance.js')){const identity=await value.observeExclusiveMaintenanceLease(lease);append({type:'lease',hostPid:process.pid,pid:identity.pid,backendStart:identity.backendStart});}return lease;};}
 if(request==='pg'&&process.env.ENTRY_CASE==='interrupted'&&!seen.has(value)){seen.add(value);const query=value.Client.prototype.query;const staged=new WeakSet();value.Client.prototype.query=function(...args){const sql=typeof args[0]==='string'?args[0]:args[0]?.text;if(this.connectionParameters?.application_name==='owasp-ai-goat-maintenance-lease'&&sql?.startsWith('INSERT INTO dvaia_maintenance.epoch_replay_profiles'))staged.add(this);const result=query.apply(this,args);if(staged.has(this)&&sql==='COMMIT'){staged.delete(this);return Promise.resolve(result).then(v=>{append({type:'committed',stage:'begin'});process.kill(process.pid,'SIGKILL');return v;});}return result;};}
 if(request.endsWith('secureshopSystemManagedEnvironment')&&process.env.ENTRY_CASE==='startup'&&!seen.has(value)){seen.add(value);value.assertReady=async()=>{append({type:'post-maintenance-start-boundary'});throw Object.assign(Error('Owned construction boundary'),{code:'OWNED_ENTRY_BOUNDARY'});};}
 return value;
};

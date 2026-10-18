'use strict';
// Owned qualification preload only. The database operation completes before its
// response is lost; no command, receipt or authority result is synthesized.
if(process.env.CTF_SETUP_APPLICATION_ISOLATED!=='1')throw Error('CTF_LOSS_FIXTURE_NOT_ADMITTED');
const fs=require('node:fs'),path=require('node:path'),{Client}=require('pg');
const root=fs.realpathSync(process.env.SETUP_PHASE_EVIDENCE_ROOT),file=path.join(root,'ctf-commit-loss.json');
const original=Client.prototype.query,pending=new WeakMap();let injected=fs.existsSync(file);
Client.prototype.query=function(...args){
 const text=typeof args[0]==='string'?args[0]:args[0]?.text,values=typeof args[0]==='string'?args[1]:args[0]?.values;
 const result=original.apply(this,args);
 if(typeof text!=='string'||!result||typeof result.then!=='function')return result;
 const insertion=text.startsWith('INSERT INTO ctf.projection_receipts(')&&values?.[2]==='student_delete';
 return result.then(value=>{
  if(insertion)pending.set(this,values[1]);
  if(text.trim().toUpperCase()==='ROLLBACK')pending.delete(this);
  if(text.trim().toUpperCase()==='COMMIT'&&pending.has(this)){
   const operationId=pending.get(this);pending.delete(this);
   if(!injected){
    if(!/^[a-f0-9-]{36}$/.test(operationId))throw Error('CTF_LOSS_OPERATION_INVALID');
    fs.writeFileSync(file,JSON.stringify({version:1,operationId,afterRealCommit:true})+'\n',{flag:'wx',mode:0o600});injected=true;
    throw Object.assign(Error('Owned response lost after real CTF commit'),{code:'ECONNRESET'});
   }
  }
  return value;
 });
};

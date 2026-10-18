'use strict';
// Absolute main code, private data-only cwd. No fixture authority injection.
async function main(input){
 const fs=require('node:fs'),path=require('node:path');
 const {privateJson}=require('./populated16-rehearsal.cjs');
 const {installation,home,admin,environment}=privateJson(input).value;
 if(fs.realpathSync(process.cwd())!==installation||path.dirname(input)!==installation||process.env.HOME!==home)throw Error('UPGRADE_CHILD_BINDING');
 Object.assign(process.env,environment);
 const cp=require('node:child_process');
 const restore=require('../../tests/fixtures/applicationMaintenanceProspectiveProcess.cjs').observeSpawn(cp,(child,args)=>{
  if(!args[2]?.detached)return;
  if(args[1]?.[1]!=='--owned-phase')throw Error('Unexpected nested group');
  const birth=cp.execFileSync('/bin/ps',['-p',String(child.pid),'-o','lstart='],{encoding:'utf8',timeout:2000}).trim();if(!birth)throw Error('Nested identity unknown');
  const evidence=process.env.SETUP_PHASE_EVIDENCE_ROOT,file=path.join(evidence,'nested-processes.json');
  const row=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):{owner:process.env.SETUP_PHASE_OWNER,parentPid:Number(process.env.REHEARSAL_NATIVE_PID),groups:[]};
  if(row.owner!==process.env.SETUP_PHASE_OWNER||row.parentPid!==Number(process.env.REHEARSAL_NATIVE_PID)||row.groups.length>=2)throw Error('Nested journal mismatch');
  row.groups.push({pid:child.pid,birth,id:require('node:crypto').randomUUID()});const temp=file+'.pending',fd=fs.openSync(temp,'wx',384);try{fs.writeFileSync(fd,JSON.stringify(row));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,file);const directoryFd=fs.openSync(evidence,fs.constants.O_RDONLY);try{fs.fsyncSync(directoryFd);}finally{fs.closeSync(directoryFd);}
 });
 try {
 await require('../../scripts/setup-application').setup({root:installation,homeDirectory:home,adminUrl:admin,upgrade:true,install:false,processEnvironment:environment});
 } finally {restore();}restore.assertRecorded();
}
if(require.main===module)main(process.argv[2]).catch(error=>{try{const fs=require('node:fs'),path=require('node:path');const receipt=require('./populated16-rehearsal.cjs').failureProjection(error);receipt.stage='actual-setup-upgrade';fs.writeFileSync(path.join(path.dirname(process.argv[2]),path.basename(process.argv[2])+'.failure.json'),JSON.stringify(receipt),{flag:'wx',mode:384});}catch{}process.exitCode=1;});
module.exports={main};

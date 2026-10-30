'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict'),{promisify}=require('node:util'),exec=promisify(require('node:child_process').execFile);
async function qualifyAuditActivation({identity,migration}){
 const install=require('../../scripts/install/audit-sql-target'),activation=require('../../scripts/install/audit-sql-activate');
 const intentFile=process.env.AUDIT_SQL_ACTIVATION_INTENT;assert.ok(intentFile,'Parent activation intent required');
 const privatePath=async(file,directory)=>{const st=await fs.lstat(file);assert.equal(st.isSymbolicLink(),false);assert.equal(directory?st.isDirectory():st.isFile(),true);assert.equal(st.uid,process.getuid());assert.equal(st.mode&0o077,0);assert.equal(await fs.realpath(file),file);};
 await privatePath(intentFile,false);const intent=JSON.parse(await fs.readFile(intentFile,'utf8'));
 const scratch=path.join(path.dirname(intentFile),'runtime','activation'),root=intent.root,homeDirectory=intent.home;
 assert.equal(root,path.join(scratch,'workspace'));assert.equal(homeDirectory,path.join(scratch,'home'));
 for(const directory of [scratch,root,homeDirectory])await privatePath(directory,true);
 const docker='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker',host='unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock';assert.equal(intent.dockerHost,host);assert.match(intent.image,/^sha256:[a-f0-9]{64}$/);
 const command=args=>exec(docker,['--host',host,...args],{timeout:120000,maxBuffer:1024*1024});
 const canonicalSourceRoot=path.resolve(__dirname,'../..');
 const checkPrerequisites=options=>activation.assertApplicationPrerequisites({...options,root:canonicalSourceRoot});

 const server=require('node:net').createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));
 const options={root,home:homeDirectory,dockerHost:host,port,run:async(_file,args)=>{try{return{exitCode:0,stdout:await (async()=>{const output=(await exec(docker,args,{timeout:120000,maxBuffer:1024*1024})).stdout;if(args.includes('image')&&args.includes('inspect'))assert.equal(JSON.parse(output)[0].Id,intent.image);return output;})()};}catch{return{exitCode:1,stdout:''};}}};const p=install.plan(options);for(const key of ['root','id','name','volume','database','dockerHost','file'])assert.equal(p[key],intent[key]);
 const environment={IDENTITY_DATABASE_URL:process.env.PG_HTTP_RUNTIME_URL,IDENTITY_MIGRATION_DATABASE_URL:process.env.PG_HTTP_MIGRATION_URL,SECURESHOP_AGENTS_MIGRATION_DATABASE_URL:process.env.PG_AUDIT_AGENTS_MIGRATION_URL};
 {
  await install.provision(options);assert.equal((await command(['inspect','--format','{{.HostConfig.RestartPolicy.Name}}',p.name])).stdout.trim(),'unless-stopped');const before=await fs.readFile(p.file,'utf8');assert.equal(JSON.parse(before).activationPending,true);
  await migration.query('REVOKE INSERT ON identity.secureshop_audit_target_admissions FROM dvaia_identity_runtime');await assert.rejects(activation.activateForSetup({root,homeDirectory,environment,checkPrerequisites}));assert.equal(await fs.readFile(p.file,'utf8'),before);await migration.query('GRANT INSERT ON identity.secureshop_audit_target_admissions TO dvaia_identity_runtime');
  assert.deepEqual(await activation.activateForSetup({root,homeDirectory,environment,checkPrerequisites}),{activationEnabled:true,preserved:false});const after=await fs.readFile(p.file,'utf8');assert.equal(JSON.parse(after).agentEnabled,true);assert.deepEqual(await activation.activateForSetup({root,homeDirectory,environment,checkPrerequisites}),{activationEnabled:true,preserved:true});assert.equal(await fs.readFile(p.file,'utf8'),after);
  const config=JSON.parse(after);await fs.writeFile(p.file,JSON.stringify({...config,enabled:false,agentEnabled:false})+'\n',{mode:0o600});const disabled=await fs.readFile(p.file,'utf8');assert.deepEqual(await activation.activateForSetup({root,homeDirectory,environment,checkPrerequisites}),{activationEnabled:false,preserved:true});assert.equal(await fs.readFile(p.file,'utf8'),disabled);
  await command(['stop',p.name]);await install.provision(options);assert.equal(JSON.parse(await fs.readFile(p.file,'utf8')).enabled,false);assert.equal((await command(['inspect','--format','{{.State.Running}}',p.name])).stdout.trim(),'true');
  console.log('AUDIT_SQL_FRESH_ACTIVATION_NATIVE_PASSED '+JSON.stringify({freshActivation:true,actualApplicationLedgerAndPrivileges:true,realPrivateDaemon:true,failedPrerequisitePreservedConfig:true,repeatByteStable:true,existingDisabledPreserved:true,stoppedOwnedContainerRestarted:true}));
 } // Parent retires declared resources after child exit and preserves config on uncertainty.
}
module.exports={qualifyAuditActivation};

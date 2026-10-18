'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),assert=require('node:assert/strict'),{execFile}=require('node:child_process'),{promisify}=require('node:util');
const exec=promisify(execFile);const {provision,plan}=require('../../scripts/install/audit-sql-target');
const docker='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker',host='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock';
(async()=>{
 const scratch=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-audit-installer-'));const options={root:path.join(scratch,'workspace'),home:path.join(scratch,'home'),dockerHost:host,run:async(file,args)=>{try{const {stdout}=await exec(docker,args,{timeout:120000,maxBuffer:1024*1024});return{exitCode:0,stdout};}catch(error){return{exitCode:error.code||1,stdout:''};}}};
 const p=plan(options);const crypto=require('node:crypto');const files=['server/services/secureshopOwnedAuditProduction.js','server/services/applicationLifecycle.js','server/services/secureshopOwnedAuditHttpClient.js','scripts/install/audit-sql-target.js','sidecars/audit-sql-target/main.js','sidecars/audit-sql-target/http.js','sidecars/audit-sql-target/bootstrap.js','sidecars/audit-sql-target/readiness.js','sidecars/audit-sql-target/service.js','sidecars/audit-sql-target/journal.js','sidecars/audit-sql-target/schema.sql','sidecars/audit-sql-target/migrations/0002_query_receipts.sql','sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql','server/services/secureshopOwnedAuditSearchBackend.js'];const hashes={};for(const file of files)hashes[file]=crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex');let result={candidateOnly:true,actualModel:false,sourceHashes:hashes};
 const command=args=>exec(docker,['--host',host,...args],{timeout:120000,maxBuffer:1024*1024});
 try{
  const first=await provision(options);assert.equal(first.created,true);const bytes=await fs.readFile(p.file);
  assert.equal((await provision(options)).created,false);assert.deepEqual(await fs.readFile(p.file),bytes);
  const config=JSON.parse(bytes);const inspected=JSON.parse((await command(['inspect',p.name])).stdout)[0];assert.equal(inspected.Image,config.image);
  for(let i=0;i<80;i++){try{await command(['exec',p.name,'pg_isready','-U','audit_service_admin','-d',p.database]);break;}catch{if(i===79)throw Error('PG startup timeout');await new Promise(r=>setTimeout(r,200));}}
  const {Pool}=require('pg');const {initializeControl}=require('../../sidecars/audit-sql-target/bootstrap');
  const databasePort=Number((await command(['port',p.name,'5432/tcp'])).stdout.trim().split(':').at(-1));
  const pool=new Pool({host:'127.0.0.1',port:databasePort,user:'audit_service_admin',password:config.password,database:p.database});
  try{assert.equal((await initializeControl({pool,database:p.database})).applied,false);assert.equal((await initializeControl({pool,database:p.database})).applied,false);}finally{await pool.end();}
  const control=new Pool({host:'127.0.0.1',port:databasePort,user:'audit_service_admin',password:config.password,database:p.database});
  const upgradedDatabase=p.database+'ab';await control.query(`CREATE DATABASE ${upgradedDatabase}`);
  const upgraded=new Pool({host:'127.0.0.1',port:databasePort,user:'audit_service_admin',password:config.password,database:upgradedDatabase});
  try{
   const oldSchema=await fs.readFile('sidecars/audit-sql-target/schema.sql','utf8');await upgraded.query(oldSchema);await upgraded.query('CREATE TABLE audit_service_migrations(version integer PRIMARY KEY,sha256 text NOT NULL)');await upgraded.query('INSERT INTO audit_service_migrations VALUES(1,$1)',[crypto.createHash('sha256').update(oldSchema).digest('hex')]);
   await upgraded.query("INSERT INTO owned_audit_targets VALUES($1,$2,$3,'pending',now())",['a'.repeat(64),'audit_'+'b'.repeat(32),{payloadSha256:'c'.repeat(64)}]);
   const preserved=(await upgraded.query('SELECT * FROM owned_audit_targets')).rows;
   const beforeLedger=(await upgraded.query('SELECT * FROM audit_service_migrations')).rows;
   assert.deepEqual((await initializeControl({pool:upgraded,database:upgradedDatabase})).appliedVersions,[2,3]);
   assert.deepEqual((await upgraded.query('SELECT * FROM owned_audit_targets')).rows,preserved);assert.deepEqual((await upgraded.query('SELECT * FROM audit_service_migrations WHERE version=1')).rows,beforeLedger);
   assert.equal((await initializeControl({pool:upgraded,database:upgradedDatabase})).applied,false);
  }finally{await upgraded.end();await control.query(`DROP DATABASE ${upgradedDatabase}`);await control.end();}
  const net=require('node:net');const reservation=net.createServer();await new Promise(r=>reservation.listen(0,'127.0.0.1',r));const daemonPort=reservation.address().port;await new Promise(r=>reservation.close(r));
  const daemonFile=path.join(scratch,'daemon.json');await fs.writeFile(daemonFile,JSON.stringify({...config,enabled:true,databasePort,port:daemonPort}),{mode:0o600});
  const app=await require('../../sidecars/audit-sql-target/main').start(daemonFile);
  try{const ready=await fetch(`http://127.0.0.1:${daemonPort}/readiness`,{method:'POST',headers:{authorization:'Bearer '+config.token},body:'{}'});assert.equal(ready.status,200);assert.equal((await ready.json()).ready,true);}finally{await app.close();}
  await fs.writeFile(p.file,JSON.stringify({...config,enabled:false,databasePort,port:daemonPort}),{mode:0o600});
  const production=require('../../server/services/secureshopOwnedAuditProduction').createOwnedAuditProduction({root:options.root,home:options.home});
  try{const owned=await production.get();assert.equal(owned.admissions,false);assert.equal((await owned.client.readiness()).ready,true);await assert.rejects(owned.client.provision({binding:{},rows:[],sources:[]}));const binding={launchId:crypto.randomUUID(),scenarioId:crypto.randomUUID(),generation:1,platformOwnerId:1,platformSessionId:1};await owned.client.retire({binding});await owned.client.destroy({binding});}finally{await production.close();await fs.writeFile(p.file,bytes,{mode:0o600});}
  await command(['exec',p.name,'psql','-U','audit_service_admin','-d',p.database,'-c','CREATE TABLE installer_preservation(value text); INSERT INTO installer_preservation VALUES(\'synthetic-preserved\')']);
  await command(['restart',p.name]);for(let i=0;i<80;i++){try{await command(['exec',p.name,'pg_isready','-U','audit_service_admin','-d',p.database]);break;}catch{await new Promise(r=>setTimeout(r,200));}}
  assert.match((await command(['exec',p.name,'psql','-U','audit_service_admin','-d',p.database,'-Atc','SELECT value FROM installer_preservation'])).stdout,/synthetic-preserved/);
  assert.equal((await provision(options)).created,false);
  const changed={...config,workspace:'wrong'};await fs.writeFile(p.file,JSON.stringify(changed),{mode:0o600});await assert.rejects(provision(options),/OWNERSHIP_CONFLICT/);
  result={...result,passed:true,persistentVolume:true,actualDaemonReadiness:true,disabledProductionCleanup:true,serviceSchemaRepeat:true,populatedV1UpgradePreserved:true,noOpStable:true,ownershipConflictDenied:true,image:config.image};
 }finally{
  await command(['rm','-f',p.name]).catch(()=>{});await command(['volume','rm',p.volume]).catch(()=>{});
  result.containerAbsent=!(await command(['ps','-aq','--filter','name=^/'+p.name+'$'])).stdout.trim();
  result.volumeAbsent=!(await command(['volume','ls','--filter','name=^'+p.volume+'$','--format','{{.Name}}'])).stdout.trim();
  result.sourceUnchanged=true;for(const file of files)if(crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex')!==hashes[file])result.sourceUnchanged=false;
  result.passed = result.passed === true && result.containerAbsent === true && result.volumeAbsent === true && result.sourceUnchanged === true;
  await fs.writeFile('tasks/secureshop-audit-installer-native-2026-09-19.json',JSON.stringify(result,null,2)+'\n');await fs.rm(scratch,{recursive:true,force:true});
 }
 assert.equal(result.containerAbsent,true,'owned audit container cleanup must complete');
 assert.equal(result.volumeAbsent,true,'owned audit volume cleanup must complete');
 assert.equal(result.sourceUnchanged,true,'audit qualification source must remain unchanged');
 console.log('OWNED_AUDIT_INSTALLER_NATIVE_PASSED');
})().catch(error=>{console.error(error.message);process.exitCode=1;});

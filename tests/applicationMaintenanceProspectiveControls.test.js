'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {observeSpawn}=require('./fixtures/applicationMaintenanceProspectiveProcess.cjs');
test('ownership observer preserves exact spawn receiver arguments options result and native error',()=>{const args=['node',['entry'],{env:{OWNED:'yes'},detached:true}],child={},calls=[],cp={spawn(...v){assert.equal(this,cp);calls.push(v);return child;}},original=cp.spawn;const restore=observeSpawn(cp,(c,a)=>{assert.equal(c,child);assert.equal(a[1],args[1]);assert.equal(a[2],args[2]);});assert.equal(cp.spawn(...args),child);assert.deepEqual(calls,[args]);restore.assertRecorded();restore();assert.equal(cp.spawn,original);const error=Error('native'),failed={spawn(){throw error;}};const stop=observeSpawn(failed,()=>assert.fail('no child'));assert.throws(()=>failed.spawn(),e=>e===error);stop();});
test('observation failure cannot change native result and cannot count as qualification',()=>{const child={},cp={spawn:()=>child},restore=observeSpawn(cp,()=>{throw Error('disk');});assert.equal(cp.spawn(),child);assert.throws(restore.assertRecorded,/Ownership observation unavailable/);restore();});

const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
test('prospective fixture leaves schema upgrades to the production admission path',()=>{
 const source=fs.readFileSync(path.join(__dirname,'fixtures/applicationMaintenanceProspectiveProcess.cjs'),'utf8');
 assert.doesNotMatch(source,/INSERT INTO dvaia_maintenance\.ledger|maintenance-migrations|0004_executable_recovery_admission/);
 assert.match(source,/runProspectiveJournalBoundMaintenance/);
});
const {admitInstallation,failureDiagnostic}=require('./fixtures/applicationMaintenanceProspectiveProcess.cjs');
test('actual helper admission binds external data directory to journal and exact synthetic source namespace',()=>{
 const source=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'prospective-source-namespace-'))),parent=path.join(source,'backups/private-recovery');fs.mkdirSync(parent,{recursive:true});
 const evidence=fs.mkdtempSync(path.join(parent,'admission-control-')),root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-installation-control-'))),owner='a'.repeat(32);fs.chmodSync(root,0o700);const st=fs.statSync(root),row={path:root,device:st.dev,inode:st.ino,uid:st.uid},file=path.join(evidence,'ownership.json');
 const write=r=>fs.writeFileSync(file,JSON.stringify({owner,evidenceRoot:evidence,privateInstallation:r}),{mode:0o600});
 try{write(row);assert.throws(()=>admitInstallation(root,evidence,owner),/INVALID/,'default main authority must not admit synthetic namespace');assert.equal(admitInstallation(root,evidence,owner,source),root);write({...row,inode:row.inode+1});assert.throws(()=>admitInstallation(root,evidence,owner,source),/IDENTITY_MISMATCH/);write(row);assert.throws(()=>admitInstallation(root,evidence,'b'.repeat(32),source),/IDENTITY_MISMATCH/);assert.throws(()=>admitInstallation(source,evidence,owner,source),/INVALID/);}
 finally{fs.rmSync(root,{recursive:true});fs.rmSync(source,{recursive:true});}
});
test('diagnostics retain bounded stage and only allowlisted codes without secret error text',()=>{
 assert.deepEqual(failureDiagnostic(Error('postgresql://secret'), 'bootstrap'),{type:'fixture-error',stage:'bootstrap',code:'PROSPECTIVE_FIXTURE_FAILED'});
 assert.equal(failureDiagnostic(Error('OWNED_JOURNAL_INVALID'),'admission').code,'OWNED_JOURNAL_INVALID');
 assert.equal(failureDiagnostic({code:'SECRET',message:'SECRET'},'secret').stage,'admission');
});
test('actual helper admits journal published by Python launcher',{skip:!process.env.PROSPECTIVE_ATOMIC_JOURNAL_CONTROL},()=>{
 const evidence=process.env.PROSPECTIVE_ATOMIC_JOURNAL_CONTROL;
 const row=JSON.parse(fs.readFileSync(path.join(evidence,'ownership.json'),'utf8'));
 assert.equal(admitInstallation(row.privateInstallation.path,evidence,row.owner),row.privateInstallation.path);
 assert.equal(fs.statSync(path.join(evidence,'ownership.json')).mode&0o777,0o600);
});
test('prospective fixture exposes only allowlisted child diagnostic without private fields',()=>{
 const result=failureDiagnostic({code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',diagnosticCode:'MAINTENANCE_INSPECTION_STORE_MISMATCH',message:'SECRET',stack:'SQL PRIVATE'},'original');assert.equal(result.diagnosticCode,'MAINTENANCE_INSPECTION_STORE_MISMATCH');assert(!JSON.stringify(result).includes('SECRET'));const unknown=failureDiagnostic({code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT',diagnosticCode:'SECRET'},'original');assert.equal(unknown.diagnosticCode,'APPLICATION_MAINTENANCE_UNAVAILABLE');assert(!JSON.stringify(unknown).includes('SECRET'));
});

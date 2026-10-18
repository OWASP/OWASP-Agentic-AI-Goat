'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createMaintenanceInstallationResolver}=require('../scripts/lib/application-maintenance-installation');
function fixture(){
 const calls=[],ids=new Map();let denied=false;
 const observe=(kind,p)=>{calls.push([kind,p]);if(denied)throw Error('private diagnostic');return{path:p,size:null,identity:{volumeSerial:42,fileId:ids.get(p)||'0000000000000001'}};};
 const resolve=createMaintenanceInstallationResolver({platform:'win32',sourceDirectory:'C:\\app',homeDirectory:'C:\\Users\\learner',fileSystem:{realpathSync:p=>p,lstatSync:()=>{throw Error('POSIX inspection forbidden');}},privateState:{inspectWorkspaceDirectory:p=>observe('workspace',p),inspectPrivateDirectory:p=>observe('private',p)}}).resolveMaintenanceInstallation;
 return{resolve,calls,ids,deny:()=>{denied=true;}};
}
test('Windows installation binding uses workspace admission and private state directories without POSIX ownership',()=>{
 const f=fixture(),r=f.resolve();assert.equal(r.sourceRoot,'C:\\app');assert.equal(r.installationRoot,'C:\\app');assert.equal(r.envPath,'C:\\app\\.env');assert.match(r.id,/^[a-f0-9]{12}$/);assert.deepEqual(f.calls.map(c=>c[0]),['workspace','workspace','private','private']);r.assertCurrent();assert(Object.isFrozen(r));
});
test('separate Windows installation root must itself be private',()=>{
 const f=fixture(),r=f.resolve('C:\\retained');assert.equal(r.homeDirectory,'C:\\retained');assert.deepEqual(f.calls.slice(0,2),[['workspace','C:\\app'],['private','C:\\retained']]);
});
test('Windows directory identity replacement and subsequent ACL denial invalidate held installation',()=>{
 for(const kind of ['identity','acl']){const f=fixture(),r=f.resolve();if(kind==='identity')f.ids.set(r.directory,'0000000000000002');else f.deny();assert.throws(r.assertCurrent,{code:'APPLICATION_MAINTENANCE_INSTALLATION_INVALID',message:'Maintenance installation unavailable'});}
});
test('noncanonical Windows installation paths are rejected before native observation',()=>{
 for(const p of ['relative','C:\\app\\..\\other','C:\\app\\']){const f=fixture();assert.throws(()=>f.resolve(p),{code:'APPLICATION_MAINTENANCE_INSTALLATION_INVALID'});assert.equal(f.calls.length,0);}
});

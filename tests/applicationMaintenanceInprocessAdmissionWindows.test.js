'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const file=require.resolve('../server/services/applicationMaintenanceInprocessAdmission');
function harness(){
 const calls=[],control={exists:true,metadataError:null,denied:false,disappear:false,bytes:Buffer.from('controlled private bytes')};
 const nativeRead=(operation,name)=>{calls.push([operation,name]);if(control.disappear)control.exists=false;if(control.denied)throw Error('private credential diagnostic');return control.bytes;};
 const native={readAndFlushPrivateFile:name=>nativeRead('private-flush',name),readAndFlushPrivateWorkspaceFile:name=>nativeRead('workspace-flush',name)};
 const fakeFs=new Proxy({lstatSync(name){calls.push(['existence',name]);if(control.metadataError)throw Object.assign(Error('private diagnostic'),{code:control.metadataError});if(!control.exists)throw Object.assign(Error('missing'),{code:'ENOENT'});return {}; }},{get(object,key){if(key in object)return object[key];return()=>{throw Error('Raw filesystem operation forbidden: '+String(key));};}});
 const module={exports:{}};const mocks={'node:fs':fakeFs,'node:path':path.win32,'../../scripts/lib/windows-private-state':native};
 vm.runInNewContext(fs.readFileSync(file,'utf8'),{require:name=>name.includes('applicationMaintenanceInprocessSources-')?{recoveryFiles:[]}:mocks[name]||require(name),module,exports:module.exports,process:{platform:'win32'},Buffer,WeakMap,Map,Object,Set,structuredClone},{filename:file});
 return{api:module.exports,calls,control};
}
const failure={code:'APPLICATION_MAINTENANCE_PREPARATION_INVALID'};
test('Windows admission separates strict private read+flush from explicit workspace read+flush',()=>{
 const h=harness();assert(h.api.privateRead('C:\\private\\journal.json').equals(h.control.bytes));assert(h.api.workspacePrivateRead('C:\\workspace\\.env').equals(h.control.bytes));
 assert.deepEqual(h.calls,[['existence','C:\\private\\journal.json'],['private-flush','C:\\private\\journal.json'],['existence','C:\\workspace\\.env'],['workspace-flush','C:\\workspace\\.env']]);
});
test('Windows optional authority omission requires exact pre-read ENOENT and never opens native handle',()=>{
 const h=harness();h.control.exists=false;assert.equal(h.api.optionalPrivateRead('C:\\private\\ctf-authority.json'),undefined);assert.throws(()=>h.api.privateRead('C:\\private\\required.json'),{code:'ENOENT'});assert(h.calls.every(c=>c[0]==='existence'));
});
test('Windows metadata uncertainty is failure, not optional absence',()=>{
 for(const code of ['EACCES','EPERM','UNKNOWN']){const h=harness();h.control.metadataError=code;assert.throws(()=>h.api.optionalPrivateRead('C:\\private\\ctf-authority.json'),failure);assert.equal(h.calls.length,1);}
});
test('Windows native flush denial stays unknown after disappearance and never falls back to read',()=>{
 for(const optional of [false,true]){const h=harness();h.control.denied=true;h.control.disappear=true;assert.throws(()=>optional?h.api.optionalPrivateRead('C:\\private\\ctf-authority.json'):h.api.workspacePrivateRead('C:\\workspace\\.env'),e=>e.code===failure.code&&!e.message.includes('credential'));assert.equal(h.calls.length,2);}
});
test('Windows admitted bytes remain bounded and private journal policy is never implicitly widened',()=>{
 for(const bytes of ['text',Buffer.alloc(1048577)]){const h=harness();h.control.bytes=bytes;assert.throws(()=>h.api.privateRead('C:\\private\\journal.json'),failure);}
 const source=fs.readFileSync(file,'utf8');assert.equal((source.match(/workspacePrivateRead\(path\.join\((?:root|value\.root),'\.env'\)\)/g)||[]).length,3);assert.equal((source.match(/\bprivateRead\(path\.join\((?:root|value\.root),'\.env'\)\)/g)||[]).length,0);
 assert(source.includes("optionalPrivateRead(path.join(directory,'ctf-authority.json'))"));assert(source.includes('fs.fsyncSync(fd)'));
});

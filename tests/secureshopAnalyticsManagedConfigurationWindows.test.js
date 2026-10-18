'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto');
const {createManagedAnalyticsConfigurationReader,validate}=require('../server/services/secureshopAnalyticsManagedConfiguration');
const {normalizePrivatePath}=require('../scripts/lib/windows-private-state');
const failure={code:'ANALYTICS_MANAGED_CONFIGURATION_INVALID'};
function fixture(){
 const root='C:\\workspace',homeDirectory='C:\\Users\\learner',id=createHash('sha256').update(path.win32.resolve(root)).digest('hex').slice(0,12),directory=path.win32.join(homeDirectory,'.dvaia',id),filename=path.win32.join(directory,'analytics-managed.json'),calls=[];
 const value={version:1,enabled:false,workspaceId:id,dockerAuthoritySha256:'a'.repeat(64),containerName:`dvaia-analytics-${id}`,containerId:'b'.repeat(64),volumeName:`dvaia-analytics-${id}-data`,imageId:'sha256:'+'c'.repeat(64),port:18095,password:'d'.repeat(64),ownerId:randomUUID(),identity:{systemIdentifier:'1234567890123456789',controlDatabase:`dvaia_analytics_control_${id}`,clusterName:`dvaia-owned-analytics-${id}`},controlSchemaSha256:'e'.repeat(64)};
 let bytes=Buffer.from(JSON.stringify(value)),present=true,metadataError,readError,directoryError,replaced=false,inspections=0;
 const error=code=>Object.assign(Error('secret private diagnostic'),{code});
 const privateState={normalizePrivatePath,inspectPrivateDirectory(file){calls.push(['inspect',file]);assert.equal(file,directory);if(directoryError)throw error(directoryError);return{path:directory,identity:{volumeSerial:1,fileId:replaced&&inspections++?'0000000000000002':'0000000000000001'}};},readPrivateFile(file){calls.push(['native-read',file]);assert.equal(file,filename);if(readError)throw error(readError);return bytes;}};
 const fileSystem={async lstat(file){calls.push(['presence',file]);assert.equal(file,filename);if(metadataError)throw error(metadataError);if(!present)throw error('ENOENT');return {};},async readFile(){throw Error('raw read forbidden');},async open(){throw Error('raw open forbidden');}};
 const read=createManagedAnalyticsConfigurationReader({filesystemPlatform:'win32',privateState,fileSystem});
 return{root,homeDirectory,value,directory,filename,calls,options:{root,homeDirectory,uid:undefined},read,setBytes:b=>{bytes=b;},missing:()=>{present=false;},metadataError:code=>{metadataError=code;},readError:code=>{readError=code;},directoryError:code=>{directoryError=code;},replace:()=>{replaced=true;}};
}
test('native optional absence succeeds without POSIX UID, directory creation or raw reads',async()=>{
 const f=fixture();f.missing();assert.equal(await f.read(f.options),null);assert.deepEqual(f.calls,[['presence',f.filename]]);
});
test('native present read preserves exact Windows workspace hash, schema and retained bytes',async()=>{
 const f=fixture(),r=await f.read(f.options);assert.equal(r.config.workspaceId,f.value.workspaceId);assert.equal(r.config.enabled,false);assert.equal(r.directory,f.directory);assert.equal(r.filename,f.filename);assert.equal(r.sha256,createHash('sha256').update(JSON.stringify(f.value)).digest('hex'));assert(Object.isFrozen(r.config));assert(Object.isFrozen(r.config.identity));assert.deepEqual(f.calls.map(c=>c[0]),['presence','inspect','native-read','inspect']);assert.equal(validate(f.value,{root:f.root,platform:'win32'}).workspaceId,f.value.workspaceId);
});
test('metadata denial, native ACL/type/reparse denial and unsafe parent are never optional absence',async()=>{
 for(const mode of ['metadata','acl','type','reparse','parent','disappeared']){const f=fixture();if(mode==='metadata')f.metadataError('EACCES');else if(mode==='parent')f.directoryError('WINDOWS_PRIVATE_STATE_DENIED');else f.readError(mode==='disappeared'?'ENOENT':'WINDOWS_PRIVATE_STATE_DENIED');await assert.rejects(f.read(f.options),error=>error.code===failure.code&&!error.message.includes('secret'));if(mode==='metadata')assert.equal(f.calls.length,1);}
});
test('foreign workspace, malformed/extra schema, oversized/nonbuffer bytes and replacement fail closed',async()=>{
 for(const mode of ['foreign','malformed','extra','oversized','nonbuffer','replaced']){const f=fixture();if(mode==='foreign')f.setBytes(Buffer.from(JSON.stringify({...f.value,workspaceId:'f'.repeat(12)})));else if(mode==='extra')f.setBytes(Buffer.from(JSON.stringify({...f.value,url:'secret'})));else if(mode==='malformed')f.setBytes(Buffer.from('secret malformed'));else if(mode==='oversized')f.setBytes(Buffer.alloc(32769));else if(mode==='nonbuffer')f.setBytes('secret');else f.replace();await assert.rejects(f.read(f.options),failure);}
});
test('noncanonical Windows lexical paths fail before optional observation',async()=>{
 for(const root of ['C:\\workspace\\..\\workspace','c:\\workspace','\\\\server\\share\\workspace','C:workspace']){const f=fixture();await assert.rejects(f.read({...f.options,root}),failure);assert.equal(f.calls.length,0);}
});

#!/usr/bin/env node
'use strict';

const crypto=require('node:crypto');
const fs=require('node:fs');
const net=require('node:net');
const os=require('node:os');
const path=require('node:path');
const dotenv=require('dotenv');
const {workspaceId}=require('./application-data-root');

const SCOPE='application-filesystem-backup-qualification-v1';
const MAGIC=Buffer.from('OWASP-AI-GOAT-FS-ARCHIVE-V1\n');
const MAX_FILE_BYTES=64*1024*1024;
const MAX_TOTAL_BYTES=512*1024*1024;
const MAX_ENTRIES=20000;
const LABEL=/^[a-z][a-z0-9_-]{0,47}$/;
const CONFIG_NAMES=Object.freeze(['provisioning.json','administrator.json','local-postgres.json','local-docker-authority.json',
  'postgres-container.env','mailpit.json','mcp-owned.env','mcp-owned-http.json','mcp-owned-shadow.json',
  'secureshop-qualified.env','audit-sql-target.json','secureshop-mcp-targets','secureshop-ssrf-targets']);
const ENVIRONMENT_ROOTS=Object.freeze({
  SS_MCP_TRUST_FIXTURE_ROOT:'private',SS_CONTROLLED_SSRF_FIXTURE_ROOT:'private',
  XENOVA_CACHE:'data',TRANSFORMERS_CACHE:'data',
});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const canonical=value=>`${JSON.stringify(value)}\n`;

function contained(parent,child){return child===parent||child.startsWith(`${parent}${path.sep}`);}
function validateMode(stat,policy){
  if(typeof process.getuid==='function'&&stat.uid!==process.getuid())throw Error('Filesystem source has foreign ownership');
  const mode=stat.mode&0o777;
  if(policy==='private'?(mode&0o077)!==0:(mode&0o022)!==0)throw Error('Filesystem source permissions are unsafe');
  return mode;
}
function readBoundedFile(filename,policy){
  let descriptor;
  try{
    descriptor=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    const before=fs.fstatSync(descriptor);validateMode(before,policy);
    if(!before.isFile()||before.nlink!==1||before.size>MAX_FILE_BYTES)throw Error('Filesystem source file exceeds limit');
    const bytes=Buffer.alloc(before.size+1);let offset=0;
    while(offset<bytes.length){const count=fs.readSync(descriptor,bytes,offset,bytes.length-offset,offset);if(!count)break;offset+=count;}
    const after=fs.fstatSync(descriptor);
    if(offset!==before.size||after.dev!==before.dev||after.ino!==before.ino||after.size!==before.size
        ||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs||after.nlink!==1)throw Error('Filesystem source changed during read');
    return {stat:before,bytes:bytes.subarray(0,offset)};
  }finally{if(descriptor!==undefined)fs.closeSync(descriptor);}
}
function inspectRoot(spec){
  if(!spec||!LABEL.test(spec.label)||!['private','data'].includes(spec.policy)||!path.isAbsolute(spec.source)
      ||path.normalize(spec.source)!==spec.source||spec.source.includes('\0'))throw TypeError('Explicit filesystem root required');
  const canonicalRoot=fs.realpathSync(spec.source);
  if(canonicalRoot!==spec.source)throw Error('Filesystem root must be canonical and contain no link at its root');
  const rootStat=fs.lstatSync(canonicalRoot);validateMode(rootStat,spec.policy);
  if(!rootStat.isDirectory()&&!rootStat.isFile())throw Error('Filesystem root must be a regular file or directory');
  const entries=[];let totalBytes=0;
  function visit(filename,relative){
    const stat=fs.lstatSync(filename);
    if(stat.isSymbolicLink()||(!stat.isDirectory()&&!stat.isFile()))throw Error('Filesystem source contains unsupported entry');
    let mode=validateMode(stat,spec.policy);
    if(stat.isFile()){
      const read=readBoundedFile(filename,spec.policy);mode=read.stat.mode&0o777;
      if(read.stat.dev!==stat.dev||read.stat.ino!==stat.ino)throw Error('Filesystem source changed during read');
      const bytes=read.bytes;totalBytes+=bytes.length;
      entries.push({label:spec.label,path:relative,type:'file',mode,size:bytes.length,sha256:sha(bytes)});
    }else{
      entries.push({label:spec.label,path:relative,type:'directory',mode,size:0,sha256:null});
      for(const name of fs.readdirSync(filename).sort()){
        if(name.includes('\0')||name==='.'||name==='..')throw Error('Invalid filesystem entry name');
        visit(path.join(filename,name),relative?`${relative}/${name}`:name);
      }
    }
    if(entries.length>MAX_ENTRIES||totalBytes>MAX_TOTAL_BYTES)throw Error('Filesystem source exceeds archive bounds');
  }
  visit(canonicalRoot,'');
  return {label:spec.label,policy:spec.policy,source:canonicalRoot,rootType:rootStat.isDirectory()?'directory':'file',entries,totalBytes};
}
function sameEntries(left,right){return JSON.stringify(left.map(({label,path,type,mode,size,sha256})=>({label,path,type,mode,size,sha256})))===JSON.stringify(right.map(({label,path,type,mode,size,sha256})=>({label,path,type,mode,size,sha256})));}
function validateAggregate(roots){if(roots.reduce((total,row)=>total+row.entries.length,0)>MAX_ENTRIES||roots.reduce((total,row)=>total+row.totalBytes,0)>MAX_TOTAL_BYTES)throw Error('Filesystem sources exceed aggregate archive bounds');}
function safeTarget(root,relative){
  if(typeof relative!=='string'||relative.includes('\0')||relative.split('/').some(part=>part==='..'||part==='.'))throw Error('Archive path invalid');
  const target=path.resolve(root,...(relative?relative.split('/'):[]));
  if(!contained(root,target))throw Error('Archive path escaped restore root');return target;
}
function writeArchive(filename,roots){
  const fd=fs.openSync(filename,'wx',0o600);try{
    fs.writeSync(fd,MAGIC);
    for(const root of roots)for(const entry of root.entries){
      const header=Buffer.from(JSON.stringify({label:entry.label,path:entry.path,type:entry.type,mode:entry.mode,size:entry.size,sha256:entry.sha256}));
      const length=Buffer.alloc(4);length.writeUInt32BE(header.length);fs.writeSync(fd,length);fs.writeSync(fd,header);
      if(entry.type==='file'){const read=readBoundedFile(entry.path?safeTarget(root.source,entry.path):root.source,root.policy);if(read.bytes.length!==entry.size||sha(read.bytes)!==entry.sha256)throw Error('Filesystem source changed during archive');fs.writeSync(fd,read.bytes);}
    }
    fs.fsyncSync(fd);
  }finally{fs.closeSync(fd);}fs.chmodSync(filename,0o600);
}
// Read-only framed archive verification; never creates restore paths.
function verifyArchive(filename, expected) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let position = 0;
  function read(length) {
    const result = Buffer.alloc(length); let done = 0;
    while (done < length) {
      const count = fs.readSync(fd, result, done, length - done, position + done);
      if (!count) throw Error('Filesystem archive truncated');
      done += count;
    }
    position += length; return result;
  }
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || !read(MAGIC.length).equals(MAGIC)) throw Error('Filesystem archive invalid');
    for (const admitted of expected) {
      const length = read(4).readUInt32BE();
      if (length < 2 || length > 8192) throw Error('Filesystem archive entry invalid');
      const entry = JSON.parse(read(length));
      if (JSON.stringify(entry) !== JSON.stringify(admitted)) throw Error('Filesystem archive entry mismatch');
      if (entry.type === 'file') {
        if (!Number.isInteger(entry.size) || entry.size < 0 || entry.size > MAX_FILE_BYTES || sha(read(entry.size)) !== entry.sha256) throw Error('Filesystem archive payload mismatch');
      } else if (entry.type !== 'directory' || entry.size !== 0) throw Error('Filesystem archive entry type invalid');
    }
    const after = fs.fstatSync(fd);
    if (position !== after.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw Error('Filesystem archive changed or contains trailing data');
    return { entries: expected.length, bytes: position, verified: true };
  } finally { fs.closeSync(fd); }
}

function restoreArchive(filename,restoreRoot,expected){
  const bytes=fs.readFileSync(filename);if(!bytes.subarray(0,MAGIC.length).equals(MAGIC))throw Error('Filesystem archive header invalid');
  let cursor=MAGIC.length;const directories=[];const observed=[];
  while(cursor<bytes.length){
    if(cursor+4>bytes.length)throw Error('Filesystem archive truncated');const headerBytes=bytes.readUInt32BE(cursor);cursor+=4;
    if(headerBytes<2||headerBytes>8192||cursor+headerBytes>bytes.length)throw Error('Filesystem archive entry invalid');
    const entry=JSON.parse(bytes.subarray(cursor,cursor+headerBytes));cursor+=headerBytes;
    const admitted=expected.find(value=>value.label===entry.label&&value.path===entry.path);
    if(!admitted||JSON.stringify(entry)!==JSON.stringify(admitted)||!['file','directory'].includes(entry.type)
        ||!Number.isInteger(entry.mode)||!Number.isInteger(entry.size)||entry.size<0||entry.size>MAX_FILE_BYTES)throw Error('Filesystem archive entry not admitted');
    const base=path.join(restoreRoot,entry.label);
    const target=safeTarget(base,entry.path);
    if(entry.type==='directory'){fs.mkdirSync(target,{recursive:true,mode:0o700});directories.push({target,mode:entry.mode});}
    else{
      if(cursor+entry.size>bytes.length)throw Error('Filesystem archive content truncated');const content=bytes.subarray(cursor,cursor+entry.size);cursor+=entry.size;
      if(sha(content)!==entry.sha256)throw Error('Filesystem archive digest mismatch');fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});
      fs.writeFileSync(target,content,{flag:'wx',mode:entry.mode});fs.chmodSync(target,entry.mode);
    }
    observed.push(entry);
  }
  directories.sort((a,b)=>b.target.length-a.target.length).forEach(value=>fs.chmodSync(value.target,value.mode));
  if(!sameEntries(observed,expected))throw Error('Filesystem archive manifest mismatch');
  return observed;
}
function assertPrivateDirectory(value,{mustBeEmpty=false}={}){
  const real=fs.realpathSync(value),stat=fs.lstatSync(real);
  if(real!==value||!stat.isDirectory()||stat.isSymbolicLink()||(typeof process.getuid==='function'&&stat.uid!==process.getuid())||(stat.mode&0o777)!==0o700||(mustBeEmpty&&fs.readdirSync(real).length))throw Error('Private owned directory required');
  return real;
}
function fsyncDirectory(directory){const descriptor=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(descriptor);}finally{fs.closeSync(descriptor);}}
function writeDurablePrivateFile(filename,bytes){const descriptor=fs.openSync(filename,'wx',0o600);try{fs.writeFileSync(descriptor,bytes);fs.fsyncSync(descriptor);}finally{fs.closeSync(descriptor);}fs.chmodSync(filename,0o600);fsyncDirectory(path.dirname(filename));}
function readPrivateConfiguration(filename,maxBytes=64*1024){try{const read=readBoundedFile(filename,'private');if(read.bytes.length>maxBytes)throw Error();return dotenv.parse(read.bytes);}catch{throw Error('Private environment file required');}}
function configuredPath(value,key){if(typeof value!=='string'||!path.isAbsolute(value)||path.normalize(value)!==value||value.includes('\0'))throw Error(`${key} must designate an absolute normalized path`);return value;}
function portOpen(port){return new Promise(resolve=>{const socket=net.createConnection({host:'127.0.0.1',port});const done=value=>{socket.destroy();resolve(value);};socket.setTimeout(200);socket.once('connect',()=>done(true));socket.once('timeout',()=>done(false));socket.once('error',()=>done(false));});}
async function requireQuiet(){for(const port of [3000,8081,8082])if(await portOpen(port))throw Error(`Application listener ${port} must be absent before filesystem backup`);}
async function qualify({roots,output},{quietCheck=requireQuiet,afterArchive=async()=>{},afterRestore=async()=>{}}={}){
  process.umask(0o077);await quietCheck();
  if(!Array.isArray(roots)||!roots.length||new Set(roots.map(row=>row.label)).size!==roots.length)throw TypeError('Distinct filesystem roots required');
  const normalized=roots.map(row=>({...row,source:path.resolve(row.source)}));
  for(let i=0;i<normalized.length;i++)for(let j=i+1;j<normalized.length;j++)if(contained(normalized[i].source,normalized[j].source)||contained(normalized[j].source,normalized[i].source))throw Error('Filesystem roots must not overlap');
  const outputPath=path.resolve(output),parent=assertPrivateDirectory(path.dirname(outputPath));
  if(path.dirname(outputPath)!==parent||normalized.some(row=>contained(row.source,outputPath)||contained(outputPath,row.source)))throw Error('Filesystem output must be separate from sources');
  fs.mkdirSync(outputPath,{mode:0o700});assertPrivateDirectory(outputPath,{mustBeEmpty:true});
  const before=normalized.map(inspectRoot),entries=before.flatMap(row=>row.entries);
  validateAggregate(before);
  const archive=path.join(outputPath,'filesystem.archive'),manifestPath=path.join(outputPath,'manifest.json');writeArchive(archive,before);fsyncDirectory(outputPath);
  await afterArchive();
  const after=normalized.map(inspectRoot);if(!before.every((row,index)=>sameEntries(row.entries,after[index].entries)))throw Error('Filesystem source changed during archive');
  const restoreRoot=path.join(outputPath,`restore-proof-${crypto.randomBytes(6).toString('hex')}`);fs.mkdirSync(restoreRoot,{mode:0o700});
  try{restoreArchive(archive,restoreRoot,entries);await afterRestore(restoreRoot);const expectedLabels=before.map(row=>row.label).sort();if(JSON.stringify(fs.readdirSync(restoreRoot).sort())!==JSON.stringify(expectedLabels))throw Error('Filesystem restore contains unexpected roots');const restored=[];for(const row of before){const target=path.join(restoreRoot,row.label);const inspected=inspectRoot({label:row.label,policy:row.policy,source:target});restored.push(...inspected.entries);}if(!sameEntries(restored,entries))throw Error('Filesystem restore differs from source');}
  finally{fs.rmSync(restoreRoot,{recursive:true,force:true});}
  const finalSource=normalized.map(inspectRoot);if(!before.every((row,index)=>sameEntries(row.entries,finalSource[index].entries)))throw Error('Filesystem source changed before qualification receipt');
  if(fs.readdirSync(outputPath).some(name=>!['filesystem.archive'].includes(name)))throw Error('Unexpected filesystem qualification output');
  const manifest={version:1,scope:SCOPE,status:'passed',activationReady:false,archive:{file:'filesystem.archive',bytes:fs.statSync(archive).size,sha256:sha(fs.readFileSync(archive))},
    roots:before.map(row=>({label:row.label,policy:row.policy,source:row.source,type:row.rootType,entries:row.entries.length,bytes:row.totalBytes})),entries,sourceUnchanged:true,ownedRestoreMatched:true,restoreRemoved:true,
    exclusions:['launcher.json','activation-backups']};
  writeDurablePrivateFile(manifestPath,canonical(manifest));
  return {scope:SCOPE,status:'passed',output:outputPath,manifestSha256:sha(fs.readFileSync(manifestPath))};
}
function inventoryPlan({workspace=path.resolve(__dirname,'..'),home=os.homedir(),environment=process.env}={}){
  const root=fs.realpathSync(workspace),id=workspaceId(root),privateRoot=path.join(home,'.owasp-ai-goat',id),envFile=path.join(root,'.env');
  let parsed={};if(fs.existsSync(envFile))parsed=readPrivateConfiguration(envFile);
  const appDataRoot=parsed.OWASP_AI_GOAT_APP_DATA_ROOT?configuredPath(parsed.OWASP_AI_GOAT_APP_DATA_ROOT,'OWASP_AI_GOAT_APP_DATA_ROOT'):path.join(privateRoot,'app-data');
  const resetKeyPath=parsed.SS_PASSWORD_RESET_KEY_PATH?configuredPath(parsed.SS_PASSWORD_RESET_KEY_PATH,'SS_PASSWORD_RESET_KEY_PATH'):path.join(privateRoot,'secureshop-reset-key.json');
  const logsRoot=parsed.LOGS_DIR?configuredPath(parsed.LOGS_DIR,'LOGS_DIR'):path.join(root,'server','logs');
  const sensitiveRoot=parsed.LEGACY_SENSITIVE_FILES_ROOT?configuredPath(parsed.LEGACY_SENSITIVE_FILES_ROOT,'LEGACY_SENSITIVE_FILES_ROOT'):path.join(root,'server','sensitive_files');
  const specs=[],bySource=new Map();
  const addSpec=spec=>{const source=path.normalize(spec.source),prior=bySource.get(source);if(prior){prior.aliases??=[];prior.aliases.push(spec.label);if(spec.policy==='private')prior.policy='private';return;}const added={...spec,source};specs.push(added);bySource.set(source,added);};
  addSpec({label:'environment',policy:'private',source:envFile});addSpec({label:'app_data',policy:'data',source:appDataRoot});
  addSpec({label:'application_logs',policy:'data',source:logsRoot});addSpec({label:'legacy_sensitive_files',policy:'data',source:sensitiveRoot});
  CONFIG_NAMES.forEach(name=>addSpec({label:`config_${name.replace(/[^a-z0-9]+/gi,'_').toLowerCase()}`,policy:'private',source:path.join(privateRoot,name)}));
  addSpec({label:'config_secureshop_reset_key_json',policy:'private',source:resetKeyPath});
  const qualifiedFile=path.join(privateRoot,'secureshop-qualified.env');
  const qualified=fs.existsSync(qualifiedFile)?readPrivateConfiguration(qualifiedFile,8192):null;
  for(const [key,policy] of Object.entries(ENVIRONMENT_ROOTS)){if(!parsed[key]||(qualified&&Object.hasOwn(qualified,key)))continue;if(key==='TRANSFORMERS_CACHE'&&parsed.XENOVA_CACHE)continue;addSpec({label:`env_${key.toLowerCase()}`,policy,source:configuredPath(parsed[key],key)});}
  if(parsed.IPI_EMAIL_PROVIDER==='mailpit'&&parsed.MAILPIT_STATE_PATH)addSpec({label:'env_mailpit_state_path',policy:'private',source:configuredPath(parsed.MAILPIT_STATE_PATH,'MAILPIT_STATE_PATH')});
  if(parsed.PLATFORM_DATABASE_ENGINE!=='postgres'&&parsed.SS_VECTOR_INDEX_DIR)addSpec({label:'env_ss_vector_index_dir',policy:'data',source:configuredPath(parsed.SS_VECTOR_INDEX_DIR,'SS_VECTOR_INDEX_DIR')});
  if(qualified)for(const key of ['SS_MCP_TRUST_FIXTURE_ROOT','SS_CONTROLLED_SSRF_FIXTURE_ROOT'])if(qualified[key])addSpec({label:`managed_${key.toLowerCase()}`,policy:'private',source:configuredPath(qualified[key],key)});
  const overlaps=[];for(let i=0;i<specs.length;i++)for(let j=i+1;j<specs.length;j++){if(contained(specs[i].source,specs[j].source)||contained(specs[j].source,specs[i].source))overlaps.push({first:specs[i].label,second:specs[j].label});}
  return {version:1,scope:SCOPE,workspace:root,workspaceId:id,excluded:['launcher.json','activation-backups'],excludedConfiguredPathKeys:['PUPPETEER_EXECUTABLE_PATH','SECURESHOP_REVIEW_RENDERER_ROOT'],qualificationBlocked:overlaps.length>0,overlaps,roots:specs.map(spec=>{let state='absent',type=null,mode=null;try{const stat=fs.lstatSync(spec.source);state='present';type=stat.isDirectory()?'directory':stat.isFile()?'file':'unsupported';mode=(stat.mode&0o777).toString(8).padStart(4,'0');}catch(error){if(error.code!=='ENOENT')throw error;}return{...spec,state,type,mode};})};
}
function parseArgs(argv){
  if(argv.length===2&&argv[0]==='--inventory-plan'&&path.isAbsolute(argv[1]))return{inventory:true,workspace:path.resolve(argv[1])};
  const roots=[];let output;for(let i=0;i<argv.length;i++){if(argv[i]==='--output'&&i+1<argv.length)output=argv[++i];else if(argv[i]==='--root'&&i+1<argv.length){const match=argv[++i].match(/^(private|data):([a-z][a-z0-9_-]{0,47})=(\/.+)$/);if(!match)throw TypeError('Invalid root argument');roots.push({policy:match[1],label:match[2],source:path.resolve(match[3])});}else throw TypeError('Usage: qualify-application-filesystem-backup.js --inventory-plan <workspace> | --output <new-directory> --root <private|data>:<label>=<absolute-path> [...]');}
  if(!output||!roots.length)throw TypeError('Output and explicit roots required');return{roots,output:path.resolve(output)};
}
if(require.main===module){let args;try{args=parseArgs(process.argv.slice(2));if(args.inventory)console.log(JSON.stringify(inventoryPlan({workspace:args.workspace}),null,2));else qualify(args).then(result=>console.log(JSON.stringify(result))).catch(error=>{console.error(JSON.stringify({scope:SCOPE,status:'failed',code:error.code||'QUALIFICATION_FAILED'}));process.exitCode=1;});}catch(error){console.error(JSON.stringify({scope:SCOPE,status:'failed',code:error.code||'INVALID_ARGUMENTS'}));process.exitCode=1;}}
module.exports={verifyArchive,SCOPE,MAX_FILE_BYTES,MAX_TOTAL_BYTES,MAX_ENTRIES,inspectRoot,writeArchive,restoreArchive,validateAggregate,inventoryPlan,parseArgs,qualify};

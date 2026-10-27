'use strict';
// FD4 is evidence, not a capability. MAIN independently recomputes these pins.
const fs=require('node:fs/promises'),native=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const REQUIRED=['tests/postgres/v03_browser_start_barrier.js','tests/postgres/ownedV03PrivateExecutors.js','tests/postgres/v03_private_executors.py',
 'tests/postgres/run-secureshop-agent-host-transport-main.py','tests/postgres/darwin_process_inventory.py',
 'tasks/runtime/node/node_modules/node/bin/node'];
const MAIN_OPTIONS=Object.freeze(('main-workspace node node-sha256 docker docker-sha256 docker-host docker-daemon current-host-profile image-id cohort browser browser-sha256 browser-root ollama-model-sha256 evidence-parent v03-native-proof-kind v03-native-receipt v03-native-receipt-sha256 v03-native-result v03-native-result-sha256 v03-source-admission v03-source-admission-sha256 v03-outer-terminal v03-outer-terminal-sha256 v03-independent-full v03-independent-full-sha256 v03-private-run-id v03-private-plan-sha256 v03-private-channel-fd v03-private-admission-fd').split(' '));
// Exact original private V03 grammar, not a generic argparse passthrough.
// MAIN still independently validates receipt contents and current executable bytes.
function validateFullMainArgv(root,runId,planSha256,argv,pins,postgres){
 if(!Array.isArray(argv)||argv.length!==1+2*MAIN_OPTIONS.length||argv[0]!==root+'/tests/postgres/run-secureshop-agent-host-transport-main.py')throw fail('V03_MAIN_GRAMMAR');
 const values={};
 for(let i=1;i<argv.length;i+=2){
  const flag=argv[i],value=argv[i+1],key=typeof flag==='string'?flag.slice(2):'';
  if(flag!=='--'+key||!MAIN_OPTIONS.includes(key)||Object.hasOwn(values,key)||typeof value!=='string'||!value||value.startsWith('--')||value.includes('\0'))throw fail('V03_MAIN_GRAMMAR');
  values[key]=value;
 }
 const exact={'main-workspace':root,node:root+'/tasks/runtime/node/node_modules/node/bin/node',docker:root+'/tasks/runtime/container/bin/docker',
  'docker-host':'unix://'+root+'/.qualification/goat-q/docker.sock','current-host-profile':'goat-q','evidence-parent':root+'/tasks/qualification',
  cohort:'merchant-listing-image-optimize-v03-browser','v03-native-proof-kind':'current-host-v1',
  'v03-private-run-id':runId,'v03-private-plan-sha256':planSha256,'v03-private-channel-fd':'3','v03-private-admission-fd':'4',
  'ollama-model-sha256':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'};
 for(const [key,value]of Object.entries(exact))if(values[key]!==value)throw fail('V03_MAIN_GRAMMAR_BINDING');
 for(const key of MAIN_OPTIONS.filter(key=>key.endsWith('-sha256')))if(!/^[a-f0-9]{64}$/.test(values[key]))throw fail('V03_MAIN_GRAMMAR_PIN');
 for(const key of ['node','docker'])if(pins?.[values[key].slice(root.length+1)]!==values[key+'-sha256'])throw fail('V03_MAIN_GRAMMAR_PIN');
 if(!postgres||values.docker!==postgres.docker||values['docker-host']!==postgres.host||values['docker-daemon']!==postgres.daemonId||values['image-id']!==postgres.image||!/^sha256:[a-f0-9]{64}$/.test(postgres.image))throw fail('V03_MAIN_GRAMMAR_POSTGRES');
 for(const key of ['v03-native-receipt','v03-native-result','v03-source-admission','v03-outer-terminal','v03-independent-full'])
  if(!values[key].startsWith(root+'/tasks/qualification/')||path.normalize(values[key])!==values[key])throw fail('V03_MAIN_GRAMMAR_PATH');
 if(!path.isAbsolute(values['browser-root'])||path.normalize(values['browser-root'])!==values['browser-root']||values.browser!==values['browser-root']+'/Contents/MacOS/Google Chrome')throw fail('V03_MAIN_GRAMMAR_BROWSER');
 return Object.freeze(values);
}
// Pure binding only: the template belongs in the reviewed parent plan before
// that plan is hashed. Neither this result nor a JSON plan mints an owner.
function bindMainArgvTemplate(root,runId,planSha256,template){
 const marker='@V03_PLAN_SHA256@';
 if(root!==path.resolve(__dirname,'../..')||! /^[a-f0-9]{32}$/.test(runId||'')
   ||! /^[a-f0-9]{64}$/.test(planSha256||'')||!Array.isArray(template)
   ||template.length>512||template[0]!==root+'/tests/postgres/run-secureshop-agent-host-transport-main.py'
   ||template.some(value=>typeof value!=='string'||value.includes('\0')||value.length>16384)
   ||template.filter(value=>value===marker).length!==1)
  throw fail('V03_MAIN_TEMPLATE');
 for(const [flag,value]of [['--v03-private-run-id',runId],['--v03-private-plan-sha256',marker],
   ['--v03-private-channel-fd','3'],['--v03-private-admission-fd','4']]){
  // argparse accepts --flag=value as an additional occurrence, with the last
  // value winning. Only the exact two-token form is admitted for authority.
  if(template.some(item=>item.startsWith(flag+'=')))throw fail('V03_MAIN_TEMPLATE');
  const indexes=template.flatMap((item,index)=>item===flag?[index]:[]);
  if(indexes.length!==1||template[indexes[0]+1]!==value)throw fail('V03_MAIN_TEMPLATE');
 }
 if(template.some(value=>value.includes(marker)&&value!==marker))throw fail('V03_MAIN_TEMPLATE');
 const mainArgv=Object.freeze(template.map(value=>value===marker?planSha256:value));
 return Object.freeze({mainArgv,expectedMainArgvSha256:sha(JSON.stringify(mainArgv))});
}
async function sourceBytes(file,limit){
 if(await fs.realpath(file)!==file)throw fail('V03_MAIN_SOURCE_PATH');
 const nodeBinary=file===path.resolve(__dirname,'../../tasks/runtime/node/node_modules/node/bin/node');
 const bound=nodeBinary?256*1024**2:limit;
 const fd=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW|native.constants.O_NONBLOCK);
 let primary,result;
 try{
  const before=await fd.stat();if(!before.isFile()||!(nodeBinary?[1,2].includes(before.nlink):before.nlink===1)||before.size>bound)throw fail('V03_MAIN_SOURCE_FILE');
  const bytes=Buffer.alloc(before.size);let offset=0;
  while(offset<bytes.length){const row=await fd.read(bytes,offset,bytes.length-offset,offset);
   if(!row.bytesRead)throw fail('V03_MAIN_SOURCE_CHANGED');offset+=row.bytesRead;}
  const after=await fd.stat();
  if(['dev','ino','nlink','size','mtimeMs','ctimeMs'].some(k=>before[k]!==after[k]))throw fail('V03_MAIN_SOURCE_CHANGED');
  result=bytes;
 }catch(error){primary=error;}
 finally{try{await fd.close();}catch(error){primary ||= error;primary.cleanupDebt=true;}}
 if(primary)throw primary;return result;
}
async function verifySources(root,pins){
 if(root!==path.resolve(__dirname,'../..')||await fs.realpath(root)!==root
   ||!pins||Object.getPrototypeOf(pins)!==Object.prototype||REQUIRED.some(key=>!Object.hasOwn(pins,key)))throw fail('V03_MAIN_SOURCE_SET');
 for(const [relative,digest]of Object.entries(pins)){
  if(relative.startsWith('/')||relative.split('/').some(p=>!p||p==='.'||p==='..')
    ||! /^[a-f0-9]{64}$/.test(digest||''))throw fail('V03_MAIN_SOURCE_PIN');
  if(sha(await sourceBytes(path.join(root,relative),128*1024**2))!==digest)throw fail('V03_MAIN_SOURCE_CHANGED');
 }
}
async function writeAdmission(owner,directory,sourcePins,parentIdentity,mainArgv){
 require('./ownedV03PrivateExecutors').assertCombinedOwner(owner);
 const root=path.resolve(__dirname,'../..'),binding=owner.binding();
 if(owner.isRevoked()||!directory.startsWith(root+'/tasks/tmp/')||await fs.realpath(directory)!==directory)
  throw fail('V03_MAIN_ADMISSION_DIRECTORY');
 const stat=await fs.stat(directory);
 if(!stat.isDirectory()||(stat.mode&0o777)!==0o700||stat.uid!==process.getuid())throw fail('V03_MAIN_ADMISSION_DIRECTORY');
 if(!parentIdentity||parentIdentity.pid!==process.pid||!Array.isArray(mainArgv)
   ||mainArgv[0]!==root+'/tests/postgres/run-secureshop-agent-host-transport-main.py'
   ||mainArgv.some(value=>typeof value!=='string'||value.includes('\0')))throw fail('V03_MAIN_ADMISSION_BINDING');
 await verifySources(root,sourcePins);owner.remainingMs();
 const packet={version:1,target:'original-v03-private-main-admission-v1',root,runId:binding.runId,
  planSha256:binding.planSha256,sourcePins,parentIdentity,mainArgv};
 const raw=Buffer.from(JSON.stringify(packet)+'\n');if(raw.length>1024**2)throw fail('V03_MAIN_ADMISSION_BOUND');
 const file=path.join(directory,'main-admission.json');let writer,reader,primary;
 try{
  writer=await fs.open(file,native.constants.O_WRONLY|native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_NOFOLLOW,0o600);
  let offset=0;while(offset<raw.length){const row=await writer.write(raw,offset,raw.length-offset);
   if(!row.bytesWritten)throw fail('V03_MAIN_ADMISSION_WRITE');offset+=row.bytesWritten;}
  await writer.sync();await writer.close();writer=null;
  const parent=await fs.open(directory,native.constants.O_RDONLY|native.constants.O_DIRECTORY|native.constants.O_NOFOLLOW);
  try{await parent.sync();}finally{await parent.close();}
  reader=await fs.open(file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
  const actual=await reader.readFile();if(!actual.equals(raw))throw fail('V03_MAIN_ADMISSION_CHANGED');
  await verifySources(root,sourcePins);owner.remainingMs();
  return Object.freeze({fd:reader.fd,file,sha256:sha(raw),close:()=>reader.close()});
 }catch(error){primary=error;primary.cleanupDebt=true;}
 finally{if(primary){for(const fd of [writer,reader])if(fd)try{await fd.close();}catch{primary.admissionCloseUnproven=true;}}}
 throw primary;
}
module.exports={writeAdmission,verifySources,bindMainArgvTemplate,validateFullMainArgv,_internals:{sourceBytes,MAIN_OPTIONS}};

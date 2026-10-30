'use strict';
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const {hash}=require('./upload-preview-contract');
const RUNTIME_ROOT='/opt/owasp-ai-goat-owned-system/upload-preview-runtime';
const MANIFEST='/usr/share/owasp-ai-goat/upload-preview-assets.json';
const ASSETS=['/usr/local/bin/node','/usr/bin/bwrap','/usr/local/libexec/owasp-ai-goat-system-config-supervisor',
 '/usr/local/libexec/owasp-ai-goat-upload-preview-init','/opt/owasp-ai-goat-owned-system/upload-preview-worker.js',
 '/opt/owasp-ai-goat-owned-system/upload-preview-contract.js','/opt/owasp-ai-goat-owned-system/upload-preview-executor.js',
 '/opt/owasp-ai-goat-owned-system/upload-preview-dependencies.js'];
function deriveRuntimeLock(lock){
 if(lock.lockfileVersion!==3||lock.packages?.['node_modules/sharp']?.version!=='0.35.4')throw Error('Exact existing sharp lock required');
 const manifest={name:'owasp-ai-goat-owned-upload-preview-runtime',version:'1.0.0',private:true,dependencies:{sharp:'0.35.4'}};
 const packages={'':{name:manifest.name,version:manifest.version,dependencies:manifest.dependencies}};
 function add(name){
  const key='node_modules/'+name;if(packages[key])return;
  const record=lock.packages[key];if(!record||!record.integrity||!/^sha512-/.test(record.integrity)||!record.resolved?.startsWith('https://registry.npmjs.org/'))throw Error('Integrity-pinned runtime dependency required: '+name);
  packages[key]=structuredClone(record);delete packages[key].dev;delete packages[key].devOptional;
  for(const child of Object.keys({...record.dependencies,...record.optionalDependencies}))add(child);
 }
 add('sharp');return{manifest,lock:{name:manifest.name,version:manifest.version,lockfileVersion:3,requires:true,packages}};
}
function filesUnder(directory){
 const files=[];
 for(const name of fs.readdirSync(directory).sort()){
  const file=path.join(directory,name),stat=fs.lstatSync(file);
  if(stat.isSymbolicLink())throw Error('Runtime package symlink not permitted: '+file);
  if(stat.isDirectory())files.push(...filesUnder(file));else if(stat.isFile())files.push(file);else throw Error('Regular runtime package file required');
 }
 return files;
}
async function buildRuntimeManifest(){
 if(process.platform!=='linux'||!['x64','arm64'].includes(process.arch)||process.getuid()!==0)throw Error('Build manifest only in owned Linux image build');
 const modules=path.join(RUNTIME_ROOT,'node_modules'),sharp=require(path.join(modules,'sharp'));
 if(sharp.versions.sharp!=='0.35.4')throw Error('Wrong sharp runtime');
 const polyglot=Buffer.from('4749463839612f2a0100800000000000ffffff21f90401000000002c00000000010001000002024401003b2a2f3d313b766f696420303b0a','hex');
 const decoded=await require('./upload-preview-worker').decodeGif(polyglot,sharp);
 const syntax=spawnSync('/usr/local/bin/node',['--check','--input-type=commonjs'],{input:polyglot,timeout:2000,maxBuffer:8192});
 if(syntax.status!==0||syntax.signal||syntax.error)throw Error('Linux Node dual-format syntax preflight failed');
 const names=['sharp','@img/colour','detect-libc','semver',`@img/sharp-linux-${process.arch}`,`@img/sharp-libvips-linux-${process.arch}`];
 for(const name of names)if(!fs.statSync(path.join(modules,name)).isDirectory())throw Error('Required native package absent');
 const files=[...ASSETS,...filesUnder(modules)];
 const native=files.filter(file=>file.endsWith('.node')||/\.so(?:\.|$)/.test(file)||file==='/usr/local/bin/node'||file==='/usr/bin/bwrap');
 if(!native.some(file=>file.endsWith('.node'))||!native.some(file=>/libvips.*\.so/.test(file)))throw Error('Native sharp/libvips files absent');
 for(const file of native){
  const result=spawnSync('ldd',[file],{encoding:'utf8',timeout:5000,maxBuffer:65536});
  if(result.status!==0||/not found/.test(result.stdout))throw Error('Native dynamic dependencies unavailable: '+file);
  for(const line of result.stdout.split('\n')){
   const found=line.match(/(?:=>\s*)?(\/[^\s()]+)/);if(found)files.push(fs.realpathSync(found[1]));
  }
 }
 const entries={};
 for(const file of [...new Set(files)].sort()){
  const stat=fs.lstatSync(file);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==0||(stat.mode&0o022))throw Error('Immutable root-owned runtime asset required: '+file);
  entries[file]=hash(fs.readFileSync(file));
 }
 const result={version:1,runtime:{nodeVersion:process.version,platform:process.platform,arch:process.arch},
  sharpVersion:sharp.versions.sharp,vipsVersion:sharp.versions.vips,runtimeRoot:RUNTIME_ROOT,files:entries};
 result.preflight={bodySha256:hash(polyglot),decoder:decoded.decoder,nodeSyntaxValid:true,originalInterpreterExecuted:false};
 fs.mkdirSync(path.dirname(MANIFEST),{recursive:true});fs.writeFileSync(MANIFEST,JSON.stringify(result),{mode:0o444});return result;
}
function verifyRuntimeManifest(){
 const stat=fs.lstatSync(MANIFEST);if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==0||stat.nlink!==1||(stat.mode&0o022))throw Error('Immutable upload preview manifest required');
 const manifest=JSON.parse(fs.readFileSync(MANIFEST,'utf8'));
 if(manifest.version!==1||manifest.runtimeRoot!==RUNTIME_ROOT||manifest.runtime.platform!=='linux'||!['x64','arm64'].includes(manifest.runtime.arch)||manifest.sharpVersion!=='0.35.4')throw Error('Upload preview manifest invalid');
 for(const file of ASSETS)if(!manifest.files[file])throw Error('Preview asset absent from manifest');
 for(const [file,digest]of Object.entries(manifest.files)){
  if(!/^[a-f0-9]{64}$/.test(digest)||!file.startsWith('/'))throw Error('Preview asset digest invalid');
  const item=fs.lstatSync(file);if(!item.isFile()||item.isSymbolicLink()||item.uid!==0||(item.mode&0o022)||hash(fs.readFileSync(file))!==digest)throw Error('Preview runtime asset changed: '+file);
 }
 for(const file of filesUnder(path.join(RUNTIME_ROOT,'node_modules')))if(!manifest.files[file])throw Error('Unrecorded runtime dependency file');
 return Object.freeze(manifest);
}
if(require.main===module){
 if(process.argv[2]==='--derive-lock'){
  const derived=deriveRuntimeLock(JSON.parse(fs.readFileSync(process.argv[3],'utf8'))),directory=path.join(__dirname,'upload-preview-runtime');
  fs.mkdirSync(directory,{recursive:true});fs.writeFileSync(path.join(directory,'package.json'),JSON.stringify(derived.manifest,null,2)+'\n');
  fs.writeFileSync(path.join(directory,'package-lock.json'),JSON.stringify(derived.lock,null,2)+'\n');
 }else if(process.argv[2]==='--build-manifest')buildRuntimeManifest().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});else throw Error('Explicit dependency action required');
}
module.exports={RUNTIME_ROOT,MANIFEST,ASSETS,deriveRuntimeLock,filesUnder,buildRuntimeManifest,verifyRuntimeManifest};

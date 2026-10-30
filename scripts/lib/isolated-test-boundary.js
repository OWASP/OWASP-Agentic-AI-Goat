'use strict';
const fs = require('node:fs');
const path = require('node:path');
const TRAVERSAL_FIXTURE='server/sensitive_files/traversal-fixtures/config/secrets.env';
const TRAVERSAL_FIXTURE_SHA256='26e275f4f01e5211b2e223ca9c0d944a8922d53e1c231029b20b18866e13b27a';
function artifactEnvironment(directory) {
  const data=path.join(directory,'data');
  return {SECURESHOP_UPLOAD_ROOT:path.join(data,'uploads'),LOGS_DIR:path.join(data,'logs'),LEGACY_SENSITIVE_FILES_ROOT:path.join(data,'legacy-sensitive'),HOME:path.join(data,'home'),USERPROFILE:path.join(data,'home'),TMPDIR:path.join(data,'tmp'),TMP:path.join(data,'tmp'),TEMP:path.join(data,'tmp'),XDG_CONFIG_HOME:path.join(data,'config'),XDG_CACHE_HOME:path.join(data,'cache'),XDG_DATA_HOME:path.join(data,'share')};
}
function absolute(value) {
  if(typeof value!=='string'||value.includes('\0')||!path.isAbsolute(value)||path.normalize(value)!==value)throw Error('Expected normalized absolute path');
  return value;
}
function canonical(value) {
  absolute(value);let parent=value;const tail=[];
  while(!fs.existsSync(parent)){const next=path.dirname(parent);if(next===parent)throw Error('Missing path ancestor');tail.unshift(path.basename(parent));parent=next;}
  return path.join(fs.realpathSync(parent),...tail);
}
function inside(value,root){return value===root||value.startsWith(root+path.sep);}
function executableFile(file){absolute(file);const actual=fs.realpathSync(file);if(!fs.statSync(actual).isFile())throw Error('Executable must be regular');fs.accessSync(actual,fs.constants.X_OK);return actual;}
function normalizeMasks(values){
  if(!Array.isArray(values))throw Error('Secrets must be an array');
  const sorted=[...new Set(values.map(canonical))].sort((a,b)=>a.length-b.length||a.localeCompare(b));
  return sorted.filter((file,index)=>!sorted.slice(0,index).some(parent=>inside(file,parent)));
}
function discoverSecrets(source, home, hostMasks = ['/Library/Keychains']) {
  if(!Array.isArray(hostMasks))throw Error('Host masks must be an array');
  hostMasks.forEach(absolute);
  source=fs.realpathSync(absolute(source));absolute(home);
  const {createCopyFilter}=require('./isolated-source-copy'),filter=createCopyFilter(source,{readPublicBuild:true}),found=[];
  const visited=new Set();
  function visit(directory){
    const actual=fs.realpathSync(directory);if(visited.has(actual))return;visited.add(actual);
    for(const entry of fs.readdirSync(directory,{withFileTypes:true})){
      const file=path.join(directory,entry.name);
      // Dependencies are separate reviewed read roots, not copied fixture data.
      if(entry.name==='node_modules')continue;
      // Built public assets are read-only inputs, not copied test data. Reject
      // aliases and still inspect every child for the ordinary secret masks.
      if(/^client[\\/]build(?:[\\/]|$)/.test(path.relative(source,file))&&entry.isSymbolicLink()){found.push(file);continue;}
      if(path.relative(source,file).split(path.sep).join('/')===TRAVERSAL_FIXTURE){
        const stat=fs.lstatSync(file);
        if(!stat.isFile()||stat.isSymbolicLink()||fs.realpathSync(file)!==path.join(source,TRAVERSAL_FIXTURE)||require('node:crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==TRAVERSAL_FIXTURE_SHA256)throw Error('Reviewed traversal fixture changed or is unsafe');
        continue;
      }
      const privateName=/^(?:platform_secrets(?:\.json)?|administrator\.json|teaching\.env|(?:private|credentials|secrets)(?:[._-].*)?)$/i.test(entry.name);
      if(privateName||!filter(file)){found.push(file);continue;}
      let stat;try{stat=fs.statSync(file);}catch(error){if(error.code==='ENOENT')continue;throw error;}
      if(stat.isDirectory())visit(file);
      else if(entry.isSymbolicLink()){
        const target=fs.realpathSync(file),name=path.basename(target);
        if(name==='.env'||name.startsWith('.env.')||/\.(?:db|sqlite|sqlite3)(?:-(?:wal|shm|journal))?$/.test(name)||/platform_secrets|administrator\.json|teaching\.env/.test(name))found.push(file);
      }
    }
  }
  visit(source);
  found.push(...hostMasks);
  for(const name of ['.aws','.ssh','.gnupg','.config/gcloud'])found.push(path.join(home,name));
  return normalizeMasks(found);
}
function linuxReadLayout(readRoots, aliases) {
  const result=[];
  for(const root of readRoots)result.push('--ro-bind',absolute(root),root);
  for(const [logical,target] of aliases){absolute(logical);absolute(target);if(logical!==target)result.push('--symlink',target,logical);}
  return result;
}
function validateMaskAssets(directory) {
  absolute(directory);
  const parent=path.join(directory,'boundary-masks'),emptyDirectory=path.join(parent,'empty-dir'),emptyFile=path.join(parent,'empty-file');
  const uid=process.getuid();
  for(const file of [directory,parent,emptyDirectory,emptyFile]) {
    const stat=fs.lstatSync(file);
    if(stat.isSymbolicLink()||fs.realpathSync(file)!==file||stat.uid!==uid||(stat.mode&0o077)!==0)throw Error('Untrusted mask asset');
    if(file===emptyFile){if(!stat.isFile()||stat.size!==0||stat.nlink!==1)throw Error('Mask file must be empty and unlinked');}
    else if(!stat.isDirectory())throw Error('Mask parent must be a private directory');
  }
  if(fs.readdirSync(emptyDirectory).length!==0)throw Error('Mask directory must be empty');
  if(fs.readdirSync(parent).sort().join(',')!=='empty-dir,empty-file')throw Error('Unexpected mask assets');
  return {emptyDirectory,emptyFile};
}
const REVIEWED_LAB_INVENTORY=Object.freeze({'credentials.json':'1c6eef81a9d339d2c751d9efd4b755e8badb303848f8ce8ec0033353b0d30734','master_key.txt':'6a3179f3d798450ddc12f6cff75ab45c4383a45695a43dfdf11c5475d806436f'});
function reviewedLabMetadata(source) {
  const directory=path.join(source,'sidecars/sandbox-runner/labfs/var/secrets');
  if(!fs.existsSync(directory))return null;
  return verifyLabMetadataInventory(directory,REVIEWED_LAB_INVENTORY);
}
function verifyLabMetadataInventory(directory,expected) {
  absolute(directory);
  if(!expected||Object.getPrototypeOf(expected)!==Object.prototype||Object.keys(expected).length!==2||Object.entries(expected).some(([name,digest])=>!['credentials.json','master_key.txt'].includes(name)||typeof digest!=='string'||!/^[a-f0-9]{64}$/.test(digest)))throw Error('Invalid lab metadata inventory');
  const stat=fs.lstatSync(directory);
  if(!stat.isDirectory()||stat.isSymbolicLink()||fs.realpathSync(directory)!==directory||fs.readdirSync(directory).sort().join(',')!==Object.keys(expected).sort().join(','))throw Error('Reviewed lab metadata inventory changed');
  const files=[];
  for(const [name,digest] of Object.entries(expected)){
    const file=path.join(directory,name),entry=fs.lstatSync(file);
    if(!entry.isFile()||entry.isSymbolicLink()||fs.realpathSync(file)!==file||require('node:crypto').createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==digest)throw Error('Reviewed lab metadata file changed');
    files.push(file);
  }
  return {directory,files};
}
function buildBoundary({platform=process.platform,source,directory,secrets,executable,args}) {
  const logicalPaths=[absolute(source),absolute(directory),absolute(executable),path.join(source,'node_modules'),path.join(source,'client/node_modules')];
  source=fs.realpathSync(absolute(source));directory=fs.realpathSync(absolute(directory));
  if(!fs.statSync(source).isDirectory()||!fs.statSync(directory).isDirectory()||inside(directory,source)||inside(source,directory))throw Error('Isolation data must be outside source');
  if(!Array.isArray(args)||args.some(arg=>typeof arg!=='string'||arg.includes('\0')))throw Error('Arguments must be strings');
  executable=executableFile(executable);
  const runtime=path.dirname(path.dirname(executable));
  if(path.basename(path.dirname(executable))!=='bin'||runtime===path.parse(runtime).root)throw Error('Expected canonical Node installation bin executable');
  const dependencies=['node_modules','client/node_modules'].map(name=>fs.realpathSync(path.join(source,name)));
  const requested=['/System','/usr','/bin','/sbin','/lib','/lib64','/Library','/etc','/private/var/db/dyld'];
  const osRoots=requested.filter(file=>fs.existsSync(file)).map(canonical);
  const readRoots=[...new Set([source,runtime,...dependencies,...osRoots])];
  const masks=normalizeMasks(secrets);
  for(const mask of masks)if([source,runtime,...dependencies,directory,executable].some(root=>inside(root,mask))||inside(mask,directory))throw Error('Secret mask conflicts with required root');
  if(platform==='darwin'){
    const command=executableFile('/usr/bin/sandbox-exec'),q=JSON.stringify;
    const lab=reviewedLabMetadata(source);
    const devices=['/dev/null','/dev/urandom','/dev/random','/dev/fd'];
    const ancestors=new Set();
    for(const leaf of [...logicalPaths,...readRoots,directory,...devices,...requested.filter(file=>fs.existsSync(file)),executable]){
      for(let parent=path.dirname(leaf);;parent=path.dirname(parent)){ancestors.add(parent);if(parent===path.dirname(parent))break;}
    }
    const profile=['(version 1)','(allow default)','(deny file-read*)','(deny file-write*)','(allow file-read* (literal "/"))',
      `(allow file-read-metadata ${[...ancestors].sort().map(root=>`(literal ${q(root)})`).join(' ')})`,
      `(allow file-read* ${[...readRoots,directory].map(root=>`(subpath ${q(root)})`).join(' ')} ${devices.map(file=>`(subpath ${q(file)})`).join(' ')})`,
      `(allow file-write* (subpath ${q(directory)}) (literal "/dev/null"))`,
      ...masks.map(file=>`(deny file-read* (subpath ${q(file)}))`),
      ...(lab?[`(allow file-read-data (literal ${q(lab.directory)}))`,
        `(allow file-read-data ${lab.files.map(file=>`(literal ${q(file)})`).join(' ')})`,`(allow file-read-metadata ${[lab.directory,...lab.files].map(file=>`(literal ${q(file)})`).join(' ')})`]:[])].join('\n');
    return {command,args:['-p',profile,executable,...args],cwd:source,readRoots,masks,missingOsRoots:requested.filter(file=>!fs.existsSync(file))};
  }
  if(platform==='linux'){
    const tool=['/usr/bin/bwrap','/bin/bwrap'].find(file=>fs.existsSync(file));if(!tool)throw Error('bubblewrap required; Linux boundary unqualified');
    const command=executableFile(tool);
    // Synthetic immutable mask assets are data, never source. Root creates them
    // before invocation; their parent must not be writable in the child.
    const {emptyDirectory,emptyFile}=validateMaskAssets(directory);
    const masking=[];for(const mask of masks){if(!fs.existsSync(mask)||!readRoots.some(root=>inside(mask,root)))continue;masking.push('--ro-bind',fs.statSync(mask).isDirectory()?emptyDirectory:emptyFile,mask);}
    const layout=linuxReadLayout(readRoots,requested.filter(file=>fs.existsSync(file)).map(name=>[name,canonical(name)]));
    return {command,args:['--unshare-user','--unshare-pid','--die-with-parent','--new-session','--cap-drop','ALL',...layout,'--proc','/proc','--dev','/dev','--bind',directory,directory,'--ro-bind',path.dirname(emptyFile),path.dirname(emptyFile),...masking,'--chdir',source,'--',executable,...args],cwd:source,readRoots,masks,missingOsRoots:requested.filter(file=>!fs.existsSync(file))};
  }
  throw Error('No qualified filesystem boundary for this platform');
}
module.exports={artifactEnvironment,discoverSecrets,buildBoundary,normalizeMasks,linuxReadLayout,validateMaskAssets,reviewedLabMetadata,verifyLabMetadataInventory};

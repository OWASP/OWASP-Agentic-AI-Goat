'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {artifactEnvironment,discoverSecrets,buildBoundary,normalizeMasks}=require('../scripts/lib/isolated-test-boundary');
test('boundary validates inputs and denies private data and directory-symlink aliases without spawning',t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'boundary-args-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=path.join(root,'source'),data=path.join(root,'data'),home=path.join(root,'home'),outside=path.join(root,'outside');for(const p of [source,data,home,outside,path.join(source,'node_modules'),path.join(source,'client'),path.join(source,'client/node_modules')])fs.mkdirSync(p);
 for(const name of ['.env','one.db','platform_secrets.json','teaching.env'])fs.writeFileSync(path.join(source,name),'synthetic');
 fs.writeFileSync(path.join(source,'.env.example'),'public');fs.writeFileSync(path.join(outside,'administrator.json'),'synthetic');fs.symlinkSync(outside,path.join(source,'linked'));fs.symlinkSync(source,path.join(outside,'cycle'));
 const hostMask=path.join(home,'synthetic-keychains');fs.mkdirSync(hostMask);
 const secrets=discoverSecrets(source,home,[hostMask]);assert.throws(()=>discoverSecrets(source,home,'bad'));assert.throws(()=>discoverSecrets(source,home,['relative']));for(const file of ['.env','one.db','platform_secrets.json','teaching.env'])assert.ok(secrets.includes(path.join(source,file)));assert.ok(secrets.includes(path.join(outside,'administrator.json')));assert.ok(!secrets.includes(path.join(source,'.env.example')));
 assert.deepEqual(normalizeMasks([path.join(source,'linked/missing/child'),path.join(outside,'missing')]),[path.join(outside,'missing')]);
 const options={source,directory:data,secrets,executable:process.execPath,args:['--test','sentinel']};
 if(process.platform==='darwin'){
 const mac=buildBoundary({...options,platform:'darwin'});assert.equal(mac.cwd,fs.realpathSync(source));assert.match(mac.args[1],/\(deny file-read\*\)/);assert.ok(mac.args[1].includes('(allow file-read* (literal "/"))'));assert.ok(!mac.args[1].includes('(subpath "/")'));
 const metadata=mac.args[1].split('\n').find(line=>line.startsWith('(allow file-read-metadata '));assert.ok(metadata);assert.ok(metadata.includes('(literal '+JSON.stringify(path.dirname(path.dirname(source)))+')'));assert.ok(!metadata.includes('subpath'));
 for(const line of mac.args[1].split('\n').filter(line=>/^\(allow file-read(?:\*|-data) /.test(line)))assert.ok(!line.includes('(subpath '+JSON.stringify(path.dirname(path.dirname(source)))+')')); assert.match(mac.args[1],/\(deny file-write\*\)/);assert.ok(mac.args[1].includes(JSON.stringify(fs.realpathSync(data))));assert.ok(mac.masks.includes(hostMask));assert.ok(!mac.readRoots.includes(os.homedir()));assert.ok(!mac.readRoots.includes(path.join(os.homedir(),'.dvaia')));assert.ok(mac.readRoots.includes(path.dirname(path.dirname(fs.realpathSync(process.execPath)))));assert.deepEqual(mac.args.slice(-3),[fs.realpathSync(process.execPath),'--test','sentinel']);
 }
 for(const change of [{args:'bad'},{args:[null]},{args:['bad\0arg']},{secrets:'bad'},{secrets:['relative']},{directory:source},{executable:'node'},{secrets:[source]},{secrets:[data]},{secrets:[path.dirname(path.dirname(fs.realpathSync(process.execPath)))]},{platform:'win32'}])assert.throws(()=>buildBoundary({...options,...change}));
 const noexec=path.join(root,'noexec');fs.writeFileSync(noexec,'synthetic',{mode:0o600});assert.throws(()=>buildBoundary({...options,executable:noexec}));assert.throws(()=>buildBoundary({...options,executable:root}));
 const artifacts=artifactEnvironment(data);assert.ok(Object.values(artifacts).every(v=>v.startsWith(data+path.sep)));for(const key of Object.keys(artifacts))assert.ok(!key.endsWith('_DB_PATH')&&!key.endsWith('_DATABASE_URL')&&key!=='DB_OUTPUT_DIR'&&key!=='SS_VECTOR_INDEX_DIR');
 assert.equal(Object.hasOwn(require('../scripts/lib/isolated-test-boundary'),'dataEnvironment'),false);assert.equal(Object.hasOwn(require('../scripts/lib/isolated-test-boundary'),'DB_FILES'),false);
});

test('Linux read layout retains absolute interpreter and shell aliases under canonical read-only roots',()=>{
 const {linuxReadLayout}=require('../scripts/lib/isolated-test-boundary');
 const roots=['/usr','/usr/bin','/usr/sbin','/usr/lib','/usr/lib64'];
 const layout=linuxReadLayout(roots,[['/bin','/usr/bin'],['/sbin','/usr/sbin'],['/lib','/usr/lib'],['/lib64','/usr/lib64']]);
 for(const root of roots)assert.ok(layout.some((value,i)=>value==='--ro-bind'&&layout[i+1]===root&&layout[i+2]===root));
 for(const name of ['bin','sbin','lib','lib64'])assert.ok(layout.some((value,i)=>value==='--symlink'&&layout[i+1]==='/usr/'+name&&layout[i+2]==='/'+name));
 assert.throws(()=>linuxReadLayout(['/usr'],[['relative','/usr/bin']]));
});

test('Linux mask assets reject symlinks, aliases, populated or public paths and hardlinks',t=>{
 const {validateMaskAssets}=require('../scripts/lib/isolated-test-boundary');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'mask-assets-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.chmodSync(root,0o700);
 const parent=path.join(root,'boundary-masks'),dir=path.join(parent,'empty-dir'),file=path.join(parent,'empty-file');fs.mkdirSync(parent,{mode:0o700});fs.mkdirSync(dir,{mode:0o700});fs.writeFileSync(file,'',{mode:0o600});
 assert.deepEqual(validateMaskAssets(root),{emptyDirectory:dir,emptyFile:file});
 for(const target of [root,parent,dir,file]){const mode=fs.statSync(target).mode&0o777;fs.chmodSync(target,0o755);assert.throws(()=>validateMaskAssets(root));fs.chmodSync(target,mode);}
 fs.writeFileSync(path.join(dir,'unexpected'),'data');assert.throws(()=>validateMaskAssets(root));fs.unlinkSync(path.join(dir,'unexpected'));
 fs.writeFileSync(file,'data');assert.throws(()=>validateMaskAssets(root));fs.writeFileSync(file,'');
 const link=path.join(root,'hardlink');fs.linkSync(file,link);assert.throws(()=>validateMaskAssets(root));fs.unlinkSync(link);
 fs.unlinkSync(file);fs.symlinkSync('/dev/null',file);assert.throws(()=>validateMaskAssets(root));fs.unlinkSync(file);fs.writeFileSync(file,'',{mode:0o600});
 const saved=path.join(root,'saved');fs.renameSync(parent,saved);fs.symlinkSync(saved,parent);assert.throws(()=>validateMaskAssets(root));fs.unlinkSync(parent);fs.renameSync(saved,parent);
 const alias=path.join(root,'alias');fs.symlinkSync(root,alias);assert.throws(()=>validateMaskAssets(alias));fs.unlinkSync(alias);
 assert.deepEqual(validateMaskAssets(root),{emptyDirectory:dir,emptyFile:file});
});

test('only exact byte-qualified canonical traversal teaching fixture avoids private-name mask',t=>{
 const relative='server/sensitive_files/traversal-fixtures/config/secrets.env';
 const bytes=fs.readFileSync(path.resolve(__dirname,'..',relative));
 assert.equal(require('node:crypto').createHash('sha256').update(bytes).digest('hex'),'58dc81956934ce9fae23e65af3674f27dc6d46f07326a54404c4a874e27d027a');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'traversal-mask-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const fixture=path.join(root,relative),privateFile=path.join(root,'server/config/secrets.env');fs.mkdirSync(path.dirname(fixture),{recursive:true});fs.mkdirSync(path.dirname(privateFile),{recursive:true});
 fs.writeFileSync(fixture,bytes);fs.writeFileSync(privateFile,bytes);
 const masks=discoverSecrets(root,root,[]);assert.ok(!masks.includes(fixture));assert.ok(masks.includes(privateFile));
 fs.appendFileSync(fixture,'changed');assert.throws(()=>discoverSecrets(root,root,[]),/Reviewed traversal fixture/);
 fs.unlinkSync(fixture);fs.symlinkSync(privateFile,fixture);assert.throws(()=>discoverSecrets(root,root,[]),/Reviewed traversal fixture/);
 fs.unlinkSync(fixture);fs.writeFileSync(fixture,bytes);
 const original=path.dirname(fixture),saved=original+'-saved';fs.renameSync(original,saved);fs.symlinkSync(saved,original);assert.throws(()=>discoverSecrets(root,root,[]),/Reviewed traversal fixture/);
});

test('reviewed lab inventory validates synthetic bytes without reading masked main bodies',t=>{
 const {verifyLabMetadataInventory}=require('../scripts/lib/isolated-test-boundary');
 const boundarySource=fs.readFileSync(require.resolve('../scripts/lib/isolated-test-boundary'),'utf8');
 assert.ok(boundarySource.includes('...masks.map(file=>`(deny file-read* (subpath ${q(file)}))`)'));
 assert.ok(!boundarySource.includes('(deny file-read-data (subpath'));
 assert.ok(boundarySource.includes('(allow file-read-data (literal ${q(lab.directory)}))'));
 assert.ok(boundarySource.includes('[lab.directory,...lab.files].map(file=>`(literal ${q(file)})`)'));

 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'lab-metadata-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=path.join(root,'source'),data=path.join(root,'data'),dir=path.join(source,'sidecars/sandbox-runner/labfs/var/secrets');fs.mkdirSync(dir,{recursive:true});fs.mkdirSync(data);
 const expected={};for(const name of ['credentials.json','master_key.txt']){const bytes=Buffer.from('synthetic metadata fixture '+name);fs.writeFileSync(path.join(dir,name),bytes);expected[name]=require('node:crypto').createHash('sha256').update(bytes).digest('hex');}
 for(const dep of ['node_modules','client/node_modules'])fs.mkdirSync(path.join(source,dep),{recursive:true});
 const known=verifyLabMetadataInventory(dir,expected);assert.equal(known.directory,dir);assert.equal(known.files.length,2);
 for(const invalid of [null,[],{}, {...expected,'../escape':'a'.repeat(64)},{...expected,'credentials.json':'bad'}])assert.throws(()=>verifyLabMetadataInventory(dir,invalid));
 assert.throws(()=>verifyLabMetadataInventory('relative',expected));
 if(process.platform==='darwin')assert.throws(()=>buildBoundary({source,directory:data,secrets:[dir],executable:process.execPath,args:[],inventory:expected}),/Reviewed lab metadata file changed/);
 const first=known.files[0],bytes=fs.readFileSync(first);fs.appendFileSync(first,'changed');assert.throws(()=>verifyLabMetadataInventory(dir,expected));fs.writeFileSync(first,bytes);
 fs.writeFileSync(path.join(dir,'extra'),'unknown');assert.throws(()=>verifyLabMetadataInventory(dir,expected));fs.unlinkSync(path.join(dir,'extra'));
 fs.unlinkSync(first);fs.symlinkSync(known.files[1],first);assert.throws(()=>verifyLabMetadataInventory(dir,expected));
});

test('supported isolated and build consumers use only the artifact environment helper',()=>{
 const root=path.resolve(__dirname,'..');
 const consumers=['scripts/test-isolated.js','scripts/test-native-browser.js','tests/adminProductionBundle.test.js','tests/postgres/run-pricing-actual-isolated.py','tests/postgres/run-secureshop-audit-central-isolated.py'];
 for(const relative of consumers){const source=fs.readFileSync(path.join(root,relative),'utf8');assert.match(source,/artifactEnvironment/);assert.doesNotMatch(source,/\bdataEnvironment\b|\bDB_FILES\b/);}
 const boundary=require('../scripts/lib/isolated-test-boundary');assert.equal(Object.hasOwn(boundary,'dataEnvironment'),false);assert.equal(Object.hasOwn(boundary,'DB_FILES'),false);
});

test('public build reads retain recursive secret masks and deny build aliases without changing copy policy',t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'build-read-mask-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const build=path.join(root,'client/build');fs.mkdirSync(build,{recursive:true});
 const publicFiles=['index.html','assets/app.js','secureshop-review-renderer/manifest.json'];
 const privateFiles=['.env','.env.local','state.db','state.db-wal','debug.log','credentials.json','secrets/private.txt'];
 for(const name of [...publicFiles,...privateFiles]){const file=path.join(build,name);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,'controlled fixture');}
 const aliasTarget=path.join(root,'unrelated.txt');fs.writeFileSync(aliasTarget,'must not be read through build alias');fs.symlinkSync(aliasTarget,path.join(build,'alias.js'));
 const masks=discoverSecrets(root,root,[]),{createCopyFilter}=require('../scripts/lib/isolated-source-copy');
 assert.ok(!masks.includes(build));
 for(const name of publicFiles){assert.ok(!masks.includes(path.join(build,name)),name);assert.equal(createCopyFilter(root)(path.join(build,name)),false);}
 for(const name of privateFiles)assert.ok(masks.some(mask=>path.join(build,name)===mask||path.join(build,name).startsWith(mask+path.sep)),name);
 assert.ok(masks.includes(aliasTarget));
 assert.throws(()=>createCopyFilter(root,{readPublicBuild:'yes'}));
});

test('macOS reviewed synthetic lab body reads are two literal files; private siblings stay denied', {skip:process.platform!=='darwin'},t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'lab-body-mask-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const source=path.join(root,'source'),data=path.join(root,'data');fs.mkdirSync(source);fs.mkdirSync(data,{mode:0o700});
 for(const name of ['node_modules','client/node_modules','sidecars/sandbox-runner/labfs/var/secrets'])fs.mkdirSync(path.join(source,name),{recursive:true});
 const relative='sidecars/sandbox-runner/labfs/var/secrets',names=['credentials.json','master_key.txt'];
 for(const name of names)fs.copyFileSync(path.join(__dirname,'..',relative,name),path.join(source,relative,name));
 const privateFile=path.join(source,'credentials.json');fs.writeFileSync(privateFile,'private controlled sentinel');
 const lab=require('../scripts/lib/isolated-test-boundary').reviewedLabMetadata(source);
 const boundary=buildBoundary({source,directory:data,secrets:discoverSecrets(source,root,[]),executable:process.execPath,args:['-e',`
 const fs=require('node:fs'),assert=require('node:assert/strict');
 for(const file of ${JSON.stringify(lab.files)})assert.ok(fs.readFileSync(file).length>0);
 assert.throws(()=>fs.readFileSync(${JSON.stringify(privateFile)}));
 process.stdout.write('exact synthetic files only');
 `]});
 const bodyLine=boundary.args[1].split('\n').find(line=>line.startsWith('(allow file-read-data ')&&line.includes(JSON.stringify(lab.files[0])));
 assert.ok(bodyLine);assert.ok(!bodyLine.includes('subpath'));
 for(const file of lab.files)assert.ok(bodyLine.includes('(literal '+JSON.stringify(file)+')'));
 assert.ok(boundary.args[1].includes('(deny file-read* (subpath '+JSON.stringify(privateFile)+'))'));
 // macOS forbids installing another Seatbelt profile inside an existing one.
 // The direct boundary suite proves this physical probe; isolated runs retain
 // every inventory/hash/literal/private-mask assertion without claiming it.
 if(process.env.DVAIA_ISOLATED_TEST_WORKSPACE){
  t.diagnostic('Nested Seatbelt installation unavailable; policy assertions only. Physical boundary probe requires direct node --test.');
 }else{
  const result=require('node:child_process').spawnSync(boundary.command,boundary.args,{cwd:boundary.cwd,encoding:'utf8',timeout:5000});
  assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'exact synthetic files only');
 }
 fs.writeFileSync(path.join(lab.directory,'extra.json'),'private');assert.throws(()=>buildBoundary({source,directory:data,secrets:[],executable:process.execPath,args:[]}),/Reviewed lab metadata inventory changed/);
});

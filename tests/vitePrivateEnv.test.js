'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const source=fs.readFileSync(path.resolve(__dirname,'../client/vite.config.mjs'),'utf8');
// Evaluate the actual config body in memory; plugin construction is inert.
const body=source.replace(/^import .*;\n/gm,'').replace('import.meta.url',"'controlled-config-url'").replace('export default defineConfig','return defineConfig');
test('private env routes both real loadEnv calls and Vite envDir away from conflicting source files',async t=>{
 const {loadEnv}=await import('../client/node_modules/vite/dist/node/index.js');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'vite-env-control-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const app=path.join(root,'app'),client=path.join(app,'client'),privateDir=path.join(root,'private');fs.mkdirSync(client,{recursive:true});fs.mkdirSync(privateDir,{mode:0o700});
 fs.writeFileSync(path.join(app,'.env'),'PORT=9991\nDVAIA_CLIENT_PORT=9992\n');fs.writeFileSync(path.join(client,'.env'),'REACT_APP_SENTINEL=source-secret\nBUILD_PATH=source-output\n');fs.writeFileSync(path.join(privateDir,'.env'),'PORT=8123\nDVAIA_CLIENT_PORT=3123\nREACT_APP_SENTINEL=private-value\nBUILD_PATH=private-output\n');
 const previous={...process.env};t.after(()=>{for(const k of Object.keys(process.env))if(!(k in previous))delete process.env[k];Object.assign(process.env,previous);});for(const k of ['PORT','DVAIA_CLIENT_PORT','REACT_APP_SENTINEL','BUILD_PATH','DVAIA_VITE_ENV_DIR'])delete process.env[k];
 const calls=[];const evaluate=value=>{const fakeProcess={env:{...process.env,...(value===undefined?{}:{DVAIA_VITE_ENV_DIR:value})},getuid:()=>process.getuid()};const config=new Function('path','fs','fileURLToPath','react','defineConfig','loadEnv','transformWithOxc','opaqueFrameCors','process',body)(path,fs,()=>path.join(client,'vite.config.mjs'),()=>({}),x=>x,(...args)=>{calls.push(args[1]);return loadEnv(...args);},()=>{},()=>({}),fakeProcess);return config({mode:'development',command:'serve'});};
 const result=evaluate(privateDir);assert.deepEqual(calls,[privateDir,privateDir]);assert.equal(result.envDir,privateDir);assert.equal(result.server.port,3123);assert.equal(result.server.proxy['/api'].target,'http://127.0.0.1:8123');assert.equal(result.build.outDir,'private-output');assert.match(result.define['process.env'],/private-value/);assert.doesNotMatch(result.define['process.env'],/source-secret/);
 calls.length=0;const normal=evaluate();assert.deepEqual(calls,[client,app]);assert.equal(Object.hasOwn(normal,'envDir'),false);assert.equal(normal.server.port,9992);
 for(const invalid of ['relative',app,client])assert.throws(()=>evaluate(invalid));const link=path.join(root,'link');fs.symlinkSync(privateDir,link);assert.throws(()=>evaluate(link));fs.chmodSync(privateDir,0o755);assert.throws(()=>evaluate(privateDir));
});
test('repository-private recorder env requires exact owned output and renderer paths',t=>{
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'vite-repository-private-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const app=path.join(root,'checkout'),client=path.join(app,'client'),parent=path.join(app,'tasks/qualification'),run=path.join(parent,'frontend-build-Abc_123'),env=path.join(run,'env');
 fs.mkdirSync(client,{recursive:true});fs.mkdirSync(parent,{recursive:true,mode:0o700});fs.mkdirSync(run,{mode:0o700});
 for(const name of ['env','tmp','cache'])fs.mkdirSync(path.join(run,name),{mode:0o700});
 const values={BUILD_PATH:path.join(run,'output/application'),TMPDIR:path.join(run,'tmp'),XDG_CACHE_HOME:path.join(run,'cache')};
 for(const [key,name] of [['REVIEW','review'],['PRODUCT_DESCRIPTION','product-description'],['MAIL','mail'],['TICKET','ticket'],['SEARCH_ECHO','search-echo'],['POLICY_OUTPUT','policy-output']])
  values[`SECURESHOP_${key}_RENDERER_OUT_DIR`]=path.join(run,`output/application/secureshop-${name}-renderer`);
 const start=source.indexOf('function repositoryPrivateEnvDirectory('),end=source.indexOf('function configuredPort(',start);
 assert.ok(start>0&&end>start);
 const check=(value,edits={})=>new Function('path','fs','process','clientRoot',`${source.slice(start,end)}\nreturn privateEnvDirectory;`)(
  path,fs,{env:{...values,...edits},getuid:()=>process.getuid()},client)(value);
 assert.equal(check(env),env);
 for(const [key,changed] of [['BUILD_PATH',path.join(run,'output/other')],['TMPDIR',path.join(root,'tmp')],
  ['XDG_CACHE_HOME',path.join(root,'cache')],['SECURESHOP_TICKET_RENDERER_OUT_DIR',path.join(root,'ticket')],
  ['SECURESHOP_POLICY_OUTPUT_RENDERER_OUT_DIR',path.join(root,'policy')]])
  assert.throws(()=>check(env,{[key]:changed}),/outside source/);
 const unrelated=path.join(app,'tasks/unrelated/env');fs.mkdirSync(unrelated,{recursive:true,mode:0o700});assert.throws(()=>check(unrelated),/outside source/);
 fs.writeFileSync(path.join(env,'.env'),'PORT=1\n');assert.throws(()=>check(env),/outside source/);fs.rmSync(path.join(env,'.env'));
 fs.chmodSync(env,0o755);assert.throws(()=>check(env),/outside source/);fs.chmodSync(env,0o700);
 fs.chmodSync(parent,0o755);assert.throws(()=>check(env),/outside source/);fs.chmodSync(parent,0o700);
 const link=path.join(run,'link');fs.symlinkSync(env,link);assert.throws(()=>check(link),/outside source/);
 const external=path.join(root,'external');fs.mkdirSync(external,{mode:0o700});assert.equal(check(external),external);
 assert.equal(check(undefined),undefined);
});
test('rendered helper creates or adopts only empty private env directory before Vite import',t=>{
 const helper=fs.readFileSync(path.resolve(__dirname,'postgres/xssRenderedViteServer.js'),'utf8');
 const a=helper.indexOf('function privateDirectory('),b=helper.indexOf('\nfunction parseArgs',a),c=helper.indexOf("  const envDir = path.join(writableRoot, 'vite-env');"),d=helper.indexOf('  process.env.PORT =',c);assert(a>=0&&b>a&&c>=0&&d>c);
 const prepare=new Function('fs','path','process','writableRoot',helper.slice(a,b)+helper.slice(c,d)+'return envDir;');
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'vite-helper-env-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));const fakeProcess={env:{},getuid:()=>process.getuid()};const env=prepare(fs,path,fakeProcess,root);assert.equal(fakeProcess.env.DVAIA_VITE_ENV_DIR,env);assert.equal(fs.statSync(env).mode&0o777,0o700);assert.equal(prepare(fs,path,fakeProcess,root),env);fs.writeFileSync(path.join(env,'.env'),'PORT=9999');assert.throws(()=>prepare(fs,path,fakeProcess,root),/empty/);fs.rmSync(env,{recursive:true});fs.symlinkSync(root,env);assert.throws(()=>prepare(fs,path,fakeProcess,root),/private directory/);
 assert.match(helper,/configLoader: 'native', cacheDir, envDir,/);
});

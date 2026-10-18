'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {ensurePuppeteerBrowserInstalled,ensureReviewRenderer,ensureMailRenderer,ensureProductDescriptionRenderer,ensureTicketRenderer,ensureSearchEchoRenderer,prepareInstalledRuntime}=require('../scripts/setup-application');
const node='C:\\Private Node runtime\\node.exe',cli='C:\\Private npm runtime\\npm-cli.js';
const renderers={loadPolicyOutputRenderer:()=>({component:{id:'SecureShop.PolicyFinalResponse',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}}),loadRenderer:()=>({sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),renderReviewCard:async value=>`<div>${value.body}</div>`}),loadProductRenderer: () => ({ componentId: 'SecureShop.Product.Description', sourceSha256: 'a'.repeat(64), artifactSha256: 'b'.repeat(64), renderProductDescription: async product => `<div>${product.description_html}</div>` }), loadMailRenderer:()=>({component:{id:'SecureShop.MailMessageBody',sourceSha256:'c'.repeat(64),artifactSha256:'d'.repeat(64)}}), loadTicketRenderer:()=>({component:{id:'SecureShop.AdminTicketBody',sourceSha256:'e'.repeat(64),artifactSha256:'f'.repeat(64)}}),loadSearchEchoRenderer:()=>({component:{id:'SecureShop.SearchEcho',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}})};

test('controlled Windows ci and renderer scripts use admitted Node/CLI and copied single-key PATH',async()=>{
 const environment={PATH:'C:\\Existing tools',Path:'C:\\Windows\\System32',CUSTOM:'keep',PUPPETEER_EXECUTABLE_PATH:'C:\\Controlled browser\\chrome.exe'},before={...environment},calls=[];
 const result=await prepareInstalledRuntime({root:'C:\\Source with spaces',install:true,platform:'win32',env:environment,admittedNpm:{command:node,prefix:[cli],environment},runCommand:async(...args)=>calls.push(args),...renderers,verifyRuntime:async()=>({controlled:true})});
 assert.deepEqual(result,{controlled:true});assert.equal(calls.length,8);
 assert.deepEqual(calls.slice(0,2).map(value=>value[1]),[[cli,'ci','--strict-peer-deps','--strict-allow-scripts'],[cli,'ci','--strict-peer-deps','--strict-allow-scripts']]);
 assert.deepEqual(calls.slice(2).map(value=>value[1]),[[cli,'run','build:review-renderer'],[cli,'run','build:mail-renderer'],[cli,'run','build:product-description-renderer'],[cli,'run','build:ticket-renderer'],[cli,'run','build:search-echo-renderer'],[cli,'run','build:policy-output-renderer']]);
 for(const [command,, ,env] of calls){assert.equal(command,node);assert.equal(env.Path,'C:\\Private Node runtime;C:\\Existing tools;C:\\Windows\\System32');assert.deepEqual(Object.keys(env).filter(key=>/^path$/i.test(key)),['Path']);assert.equal(env.CUSTOM,'keep');assert.notEqual(env,environment);}
 assert.deepEqual(environment,before);
});

test('controlled Windows no-install rebuilds renderers without package/browser installation',async()=>{
 const calls=[];await prepareInstalledRuntime({root:'C:\\Source',install:false,platform:'win32',env:{},admittedNpm:{command:node,prefix:[cli],environment:{}},runCommand:async(...args)=>calls.push(args),loadPuppeteer:()=>assert.fail('no-install must not install a browser'),...renderers,verifyRuntime:async()=>({})});
 assert.deepEqual(calls.map(value=>value[1]),[[cli,'run','build:review-renderer'],[cli,'run','build:mail-renderer'],[cli,'run','build:product-description-renderer'],[cli,'run','build:ticket-renderer'],[cli,'run','build:search-echo-renderer'],[cli,'run','build:policy-output-renderer']]);assert(calls.every(value=>value[3].Path==='C:\\Private Node runtime'));
});

test('controlled Windows renderer fallback admits supplied npm CLI and invokes direct Node with no shell command',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'renderer npm path '));try{
  const npmCli=path.join(directory,'npm-cli.js');await fs.writeFile(npmCli,'controlled npm fixture never executed');const env={npm_execpath:npmCli,Path:'C:\\Existing'},before={...env};let probes=0;const calls=[];
  const options={root:directory,env,platform:'win32',execute:async(command,args,opts)=>{probes++;assert.equal(command,process.execPath);assert.deepEqual(args,[await fs.realpath(npmCli),'--version']);assert.equal(opts.timeout,10000);return{stdout:'99.0.0\n'};},runCommand:async(...args)=>calls.push(args),...renderers};
  await ensureReviewRenderer(options);await ensureMailRenderer(options);await ensureProductDescriptionRenderer(options);await ensureTicketRenderer(options);await ensureSearchEchoRenderer(options);assert.equal(probes,5);
  const canonicalCli=await fs.realpath(npmCli);assert(calls.every(value=>value[0]===process.execPath&&value[1][0]===canonicalCli&&value[3].Path.startsWith(path.win32.dirname(process.execPath)+';')));assert.deepEqual(env,before);
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});

async function browserFixture(t,bin='./lib/puppeteer/node/cli.js'){
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'Windows Puppeteer CLI '));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const packageRoot=path.join(root,'node_modules','puppeteer'),cli=path.join(packageRoot,'lib','puppeteer','node','cli.js'),shim=path.join(root,'node_modules','.bin','puppeteer'),browser=path.join(root,'controlled browser.exe');
 await fs.mkdir(path.dirname(cli),{recursive:true});await fs.mkdir(path.dirname(shim),{recursive:true});await fs.writeFile(cli,'// owned fixture JavaScript CLI, never executed');await fs.writeFile(shim,'#!/bin/sh\nexec node "$@"\n');await fs.writeFile(path.join(packageRoot,'package.json'),JSON.stringify({bin}));
 return{root,packageRoot,cli,shim,browser};
}

test('controlled Windows browser installer selects declared JavaScript CLI instead of Windows shell shim',async t=>{
 const f=await browserFixture(t),calls=[];
 const result=await ensurePuppeteerBrowserInstalled({root:f.root,env:{},platform:'win32',loadPuppeteer:()=>({executablePath:()=>f.browser}),runCommand:async(...args)=>{calls.push(args);await fs.writeFile(f.browser,'controlled executable fixture',{mode:0o700});}});
 assert.equal(result.downloaded,true);assert.equal(calls.length,1);assert.equal(calls[0][0],process.execPath);assert.deepEqual(calls[0][1],['--use-system-ca',await fs.realpath(f.cli),'browsers','install','chrome']);assert.equal(calls[0][4].timeoutMs,600000);assert.notEqual(calls[0][1][1],f.shim);
});

test('controlled Windows package bin object works and existing browser performs no install command',async t=>{
 const f=await browserFixture(t,{puppeteer:'./lib/puppeteer/node/cli.js'});await fs.writeFile(f.browser,'controlled existing browser',{mode:0o700});
 const result=await ensurePuppeteerBrowserInstalled({root:f.root,env:{},platform:'win32',loadPuppeteer:()=>({executablePath:()=>f.browser}),runCommand:async()=>assert.fail('existing executable must not trigger download')});assert.equal(result.downloaded,false);
});

test('controlled Windows browser CLI outside its package or non-JavaScript bin fails before commands',async t=>{
 for(const bin of ['../../outside.js','./shell.sh']){
  const f=await browserFixture(t,bin),target=path.resolve(f.packageRoot,bin);await fs.writeFile(target,'controlled invalid CLI');
  await assert.rejects(ensurePuppeteerBrowserInstalled({root:f.root,env:{},platform:'win32',loadPuppeteer:()=>({executablePath:()=>f.browser}),runCommand:async()=>assert.fail('unadmitted CLI must not execute')}),/outside its package/);
 }
});

'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const ROOT=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopAdminOwnedBrowserAdmission.js'),'utf8');
const evidenceSource=fs.readFileSync(path.join(__dirname,'fixtures/secureshopNativeEvidencePath.js'),'utf8');
function setup(cohort='admin-policy-chat-browser') {
 const prefixes={'admin-policy-chat-browser':'dvaia-role-admin-policy-','admin-audit-browser':'dvaia-role-admin-audit-','admin-acl-chat-browser':'dvaia-q64-admin-acl-'};
 const gates={'admin-policy-chat-browser':'SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE','admin-audit-browser':'SECURESHOP_ADMIN_AUDIT_CHAT_BROWSER_NATIVE','admin-acl-chat-browser':'SECURESHOP_ADMIN_ACL_CHAT_BROWSER_NATIVE'};
 const run=ROOT+'/tasks/qualification/run-test',tmp=run+'/runtime/tmp',home=run+'/runtime/home';
 const args={cohort,root:ROOT,evidencePath:run+'/'+cohort+'.json',profile:tmp+'/'+prefixes[cohort]+'abc',executablePath:'/owned/chrome',origin:'http://127.0.0.1:12345'};
 const env={[gates[cohort]]:'1',DOCKER_HOST:'unix://'+ROOT+'/.qualification/goat-q/docker.sock',DVAIA_CURRENT_MAIN_WORKSPACE:ROOT,TMPDIR:tmp,MAC_CHROMIUM_TMPDIR:tmp,XDG_CACHE_HOME:home+'/.cache',XDG_CONFIG_HOME:home+'/.config',PUPPETEER_EXECUTABLE_PATH:args.executablePath};
 const proc={env,cwd:()=>ROOT,getuid:()=>501};
 const info=p=>({isDirectory:()=>!p.endsWith('docker.sock'),isSocket:()=>p.endsWith('docker.sock'),isSymbolicLink:()=>false,uid:501,mode:0o700});
 const mockfs={lstatSync:p=>{if(p.endsWith('.json'))throw Object.assign(Error('absent'),{code:'ENOENT'});return info(p)},realpathSync:p=>p};
 function load(text,require){const module={exports:{}};vm.runInNewContext(text,{module,exports:module.exports,require,process:proc,URL});return module.exports;}
 const evidence=load(evidenceSource,n=>n==='node:fs'?mockfs:require(n));
 const api=load(source,n=>n==='node:fs/promises'?{lstat:async p=>info(p),realpath:async p=>p,access:async()=>{}}:n==='./secureshopNativeEvidencePath'?evidence:require(n));
 return{args,env,api};
}
test('three exact owned cohorts use Inventory argument contract',async()=>{
 const inventory=fs.readFileSync(path.join(__dirname,'fixtures/secureshopInventoryCurrentHostAdmission.js'),'utf8');
 const expected=vm.runInNewContext(inventory.match(/args: (\[[\s\S]*?\]) \}\);/)[1]);
 for(const name of ['admin-policy-chat-browser','admin-audit-browser','admin-acl-chat-browser']){const x=setup(name);assert.deepEqual(Array.from(await x.api.browserArgs(x.args)),Array.from(expected));}
});
test('wrong scope, profile, origin, environment and receipt deny',async()=>{
 const changes=[x=>x.args.cohort='policy-template-browser',x=>x.args.profile='/foreign/profile',x=>x.args.profile=x.args.profile.replace('admin-policy','admin-audit'),x=>x.args.origin='https://example.org',x=>x.args.origin='http://127.0.0.1:12345/path',x=>x.env.TMPDIR='/tmp',x=>x.env.SECURESHOP_ADMIN_POLICY_CHAT_BROWSER_NATIVE='0',x=>x.args.evidencePath=x.args.evidencePath.replace('admin-policy','admin-audit')];
 for(const change of changes){const x=setup();change(x);await assert.rejects(x.api.browserArgs(x.args));}
});
test('historical external path gets no sandbox-disabling flags',async()=>{const x=setup();x.env.DOCKER_HOST='unix:///external/docker.sock';x.args.evidencePath='/external/admin-policy-chat-browser.json';assert.equal((await x.api.browserArgs(x.args)).length,0);});
test('actual three selected launch expressions invoke admission before mocked Puppeteer effect',async()=>{
 const role=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const acl=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneAdminAclChatRendered.integration.test.js'),'utf8');
 for(const cohort of ['admin-policy-chat-browser','admin-audit-browser','admin-acl-chat-browser']){
  const x=setup(cohort);let launches=0,admissions=0;
  const scope={browser:null,workspace:ROOT,evidencePath:x.args.evidencePath,profile:x.args.profile,executablePath:x.args.executablePath,origin:x.args.origin,a:{workspace:ROOT,evidence:x.args.evidencePath,browser:x.args.executablePath},
   ADMIN_POLICY_BROWSER:cohort==='admin-policy-chat-browser',ADMIN_AUDIT_BROWSER:cohort==='admin-audit-browser',POLICY_TEMPLATE_BROWSER:false,USER_LOOKUP_BROWSER:false,policyInstructionBrowserAdmission:null,q05BrowserAdmission:null,mailActionsAdmission:null,adminConfirmationAdmission:null,adminResetAdmission:null,inventoryChatAdmission:null,Q05_REVIEW_BROWSER:false,
   require:n=>n==='puppeteer'?{launch:async options=>{launches++;assert.equal(admissions,1);return options;}}:{browserArgs:async args=>{admissions++;return x.api.browserArgs(args);}}};
  const body=cohort==='admin-acl-chat-browser'?acl.slice(acl.indexOf("    browser = await require('puppeteer').launch"),acl.indexOf('    earlyBrowserDiagnostic =')):role.slice(role.indexOf('    const userLookupBrowserAdmission ='),role.indexOf('    earlyBrowserDiagnostic ='));
  const result=await vm.runInNewContext(`(async()=>{${body};return browser})()`,scope);
  assert.equal(launches,1);assert(result.args.includes('--no-sandbox'));assert.equal(result.executablePath,x.args.executablePath);
 }
});
test('actual launch seams preserve template fallback and original timeouts',()=>{
 const role=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const acl=fs.readFileSync(path.join(__dirname,'postgres/secureshopStandaloneAdminAclChatRendered.integration.test.js'),'utf8');
 assert(role.includes("ADMIN_POLICY_BROWSER && !POLICY_TEMPLATE_BROWSER ? 'admin-policy-chat-browser'"));
 assert(role.includes('adminOwnedBrowserScope || policyInstructionBrowserAdmission'));
 assert(acl.includes(".browserArgs({ cohort: 'admin-acl-chat-browser', root: a.workspace"));
 assert(acl.includes("timeout: 540000"));new vm.Script(role);new vm.Script(acl);
 const wrapper=fs.readFileSync(path.join(ROOT,'tasks/run-in-repository.sh'),'utf8');
 assert(wrapper.includes('exec /usr/bin/sandbox-exec -D "REPO_ROOT=$repo_root" -f "$repo_root/tasks/repository-only.sb" "$@"'));
 const profile=fs.readFileSync(path.join(ROOT,'tasks/repository-only.sb'),'utf8');assert(profile.includes('(deny file-write*)'));assert(profile.includes('(subpath (param "REPO_ROOT"))'));
});

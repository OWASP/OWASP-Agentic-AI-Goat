'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const path=require('node:path');
const {plan,qualifiedSource}=require('../scripts/install/secureshop-owned-pricing');
test('qualified source matches retained actual local package evidence',()=>{
 const root=path.resolve(__dirname,'..'),source=qualifiedSource(root);
 assert.equal(source.sha256,require('../tests/release-inputs/sidecar-pricing-package-qualified-2026-09-26.json').package.sha256);
 assert.ok(Object.isFrozen(source.files));
});
test('unsupported architecture and invalid explicit port fail before Docker or writes',async()=>{
 for(const options of [{architecture:'x64'},{architecture:'arm64',port:0},{architecture:'arm64',port:'8093'}])await assert.rejects(plan({...options,execute:()=>assert.fail('must not probe')}));
});
test('owned authority plan is repeatable and nonmutating; package drift rejects before daemon access',async t=>{
 const fs=require('node:fs'),os=require('node:os');
 const home=fs.mkdtempSync(path.join(os.tmpdir(),'pricing-plan-')),root=path.join(home,'source');fs.mkdirSync(root);t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const {PRICING_PACKAGE_FILES:files,capturePricingPackage}=require('../server/services/secureshopPricingPackage');
 for(const relative of files){const target=path.join(root,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,`synthetic package fixture: ${relative}\n`);}
 // Synthetic package exercises integrity/planning; the first test separately checks actual qualified source.
 fs.writeFileSync(path.join(root,'sidecars/sandbox-runner/owned-pricing-http/local-package-manifest.json'),JSON.stringify({...capturePricingPackage(root),qualification:'tasks/sidecar-pricing-package-qualified-2026-09-26.json'}));
 const id=require('../scripts/application-data-root').workspaceId(root),directory=path.join(home,'.owasp-ai-goat',id);fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const file=path.join(directory,'local-docker.json');fs.writeFileSync(file,JSON.stringify({version:1,workspaceId:id,host:'unix:///tmp/pricing-owned.sock',daemonId:'test-owned-daemon',source:'environment-host'}),{mode:0o600});
 const before=fs.readFileSync(file);let probes=0;
 const options={root,home,architecture:'arm64',port:28093,execute:async(_file,args)=>{probes++;assert.deepEqual(args.slice(-3),['info','--format','{{json .ID}}']);return{stdout:'"test-owned-daemon"'};}};
 assert.equal((await plan({...options,port:undefined})).port,8096);
 const result=await plan(options);assert.deepEqual(await plan(options),result);assert.equal(result.mutating,false);assert.equal(result.enabled,false);assert.equal(result.port,28093);assert.deepEqual(fs.readdirSync(directory),['local-docker.json']);assert.deepEqual(fs.readFileSync(file),before);assert.equal(probes,3);
 fs.appendFileSync(path.join(root,files[0]),'\n# drift\n');await assert.rejects(plan(options),{code:'PRICING_PACKAGE_SOURCE_CHANGED'});assert.equal(probes,3);
});

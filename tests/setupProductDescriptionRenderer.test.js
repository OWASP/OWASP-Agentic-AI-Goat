'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {ensureProductDescriptionRenderer,prepareInstalledRuntime}=require('../scripts/setup-application');
const artifact=()=>({componentId:'SecureShop.Product.Description',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64),
  renderProductDescription:async product=>`<div>${product.description_html}</div>`});

test('setup builds the exact product description renderer through admitted npm and verifies its rendered field',async()=>{
 const calls=[],root=path.resolve('/owned/repo'),environment={CUSTOM:'retained'},admittedNpm={command:'/owned/node',prefix:['/owned/npm.cjs'],environment};
 const result=await ensureProductDescriptionRenderer({root,admittedNpm,
  runCommand:async(command,args,cwd,env)=>{calls.push('build');assert.equal(command,admittedNpm.command);assert.deepEqual(args,['/owned/npm.cjs','run','build:product-description-renderer']);assert.equal(cwd,path.join(root,'client'));assert.equal(env,environment);},
  loadProductRenderer:options=>{calls.push('load');assert.deepEqual(options,{root:path.join(root,'client/build/secureshop-product-description-renderer')});return {...artifact(),renderProductDescription:async product=>{calls.push('render');assert.deepEqual(Object.keys(product).sort(),['description_html','id']);return `<div>${product.description_html}</div>`;}};}});
 assert.deepEqual(calls,['build','load','render']);assert.deepEqual(result,{artifactReady:true,componentId:'SecureShop.Product.Description',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)});assert.equal(result.ready,undefined);
});

test('failed product build or invalid renderer stops before model/browser/database readiness',async t=>{
 await assert.rejects(ensureProductDescriptionRenderer({root:'/owned',runCommand:async()=>{throw Error('build failed');},loadProductRenderer:()=>assert.fail('load after failed build')}),/build failed/);
 for(const [name,change]of Object.entries({component:r=>r.componentId='Wrong',source:r=>r.sourceSha256='bad',artifact:r=>r.artifactSha256='bad',missingMethod:r=>delete r.renderProductDescription,empty:r=>r.renderProductDescription=async()=>'',wrongField:r=>r.renderProductDescription=async p=>String(p.description)})){
  await t.test(name,async()=>{const renderer=artifact();change(renderer);await assert.rejects(prepareInstalledRuntime({root:'/owned',install:false,env:{},runCommand:async()=>{},
   loadRenderer:()=>({renderReviewCard:async p=>p.body}),loadMailRenderer:()=>({component:{id:'SecureShop.MailMessageBody',sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)}}),
   loadProductRenderer:()=>renderer,verifyRuntime:()=>assert.fail('must not advance readiness')}),/product description renderer verification failed/);});
 }
});

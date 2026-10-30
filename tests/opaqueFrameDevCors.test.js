'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
function bounded(promise,label,ms=10000){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(label+' deadline')),ms);})]).finally(()=>clearTimeout(timer));}
const request=(url,options={})=>fetch(url,{...options,signal:AbortSignal.timeout(10000)});
async function owned(t,prefix){
 const root=await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()),prefix));
 const state={root,server:null,browser:null};
 t.after(async()=>{
  const errors=[];
  try{if(state.browser)await bounded(state.browser.close(),'browser close',5000);}catch(error){errors.push(error);}
  try{if(state.server)await bounded(state.server.close(),'Vite close',5000);}catch(error){errors.push(error);}
  if(errors.length)throw new AggregateError(errors,'Owned browser cleanup failed; data retained');
  await fs.rm(root,{recursive:true,force:true});
 });return state;
}
test('actual Vite serves public modules to opaque frames without allowing opaque API or foreign-origin reads',{timeout:60000},async t=>{
 const owner=await owned(t,'owasp-ai-goat-frame-cors-'),root=owner.root;
 const {createServer}=await import('../client/node_modules/vite/dist/node/index.js');
 const {opaqueFrameCors}=await import('../client/vite.opaque-frame-cors.mjs');
 await fs.mkdir(path.join(root,'src'));await fs.mkdir(path.join(root,'assets'));
 await fs.writeFile(path.join(root,'src/fixture.js'),'export const fixture = true;');
 await fs.writeFile(path.join(root,'assets/fixture.js'),'export const fixture = true;');
 await fs.writeFile(path.join(root,'index.html'),'<!doctype html><html><body>Owned frame host</body></html>');
 const server=owner.server=await createServer({root,configFile:false,plugins:[opaqueFrameCors()],logLevel:'silent',server:{host:'127.0.0.1',port:0,watch:null}});
 await bounded(server.listen(),'Vite listen');const base=`http://127.0.0.1:${server.httpServer.address().port}`;
 for(const method of ['GET','HEAD']){
  for(const asset of ['/src/fixture.js','/assets/fixture.js']){
   const response=await request(base+asset,{method,headers:{Origin:'null'}});
   assert.equal(response.status,200);assert.equal(response.headers.get('access-control-allow-origin'),'null');
  }
 }
 for(const target of ['/api/auth/status','/src/../api/admin/users']){
  const response=await request(base+target,{headers:{Origin:'null'}});
  assert.equal(response.headers.get('access-control-allow-origin'),null);
 }
 const foreign=await request(base+'/src/fixture.js',{headers:{Origin:'https://outside.invalid'}});
 assert.equal(foreign.headers.get('access-control-allow-origin'),null);
 const browser=owner.browser=await require('puppeteer').launch({headless:true,userDataDir:path.join(root,'browser-profile'),timeout:15000});
 const page=await browser.newPage();await page.goto(base,{timeout:10000});
 await page.evaluate(moduleUrl=>{
  const frame=document.createElement('iframe');frame.sandbox='allow-scripts';
  window.addEventListener('message',event=>{
   if(event.source===frame.contentWindow&&event.origin==='null'&&event.data?.fixture===true)window.opaqueModuleLoaded=true;
  });
  frame.srcdoc=`<script type="module">import {fixture} from ${JSON.stringify(moduleUrl)};parent.postMessage({fixture},'*');</script>`;
  document.body.appendChild(frame);
 },base+'/src/fixture.js');
 await page.waitForFunction(()=>window.opaqueModuleLoaded===true,{timeout:10000});
});

test('actual Vite preview serves built assets to opaque frames without opening API paths',{timeout:60000},async t=>{
 const owner=await owned(t,'owasp-ai-goat-frame-preview-cors-'),root=owner.root;
 const dist=path.join(root,'dist');await fs.mkdir(path.join(dist,'assets'),{recursive:true});
 await fs.writeFile(path.join(dist,'index.html'),'<!doctype html><html><body>Preview</body></html>');
 await fs.writeFile(path.join(dist,'assets/frame.js'),'export const frame = true;');
 const {preview}=await import('../client/node_modules/vite/dist/node/index.js');
 const {opaqueFrameCors}=await import('../client/vite.opaque-frame-cors.mjs');
 const server=owner.server=await preview({root,configFile:false,plugins:[opaqueFrameCors()],logLevel:'silent',
  build:{outDir:'dist'},preview:{host:'127.0.0.1',port:0,strictPort:false}});
 const base=`http://127.0.0.1:${server.httpServer.address().port}`;
 for(const method of ['GET','HEAD']){
  const asset=await request(base+'/assets/frame.js',{method,headers:{Origin:'null'}});
  assert.equal(asset.status,200);assert.equal(asset.headers.get('access-control-allow-origin'),'null');
 }
 const api=await request(base+'/api/secureshop/v2/auth/login',{headers:{Origin:'null'}});
 assert.equal(api.headers.get('access-control-allow-origin'),null);
 const foreign=await request(base+'/assets/frame.js',{headers:{Origin:'https://outside.invalid'}});
 assert.equal(foreign.headers.get('access-control-allow-origin'),null);
});

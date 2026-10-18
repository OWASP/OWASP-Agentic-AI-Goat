'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('email and upload HTTP routes await every tool and preserve inline content and rejected errors',async()=>{
 const original=Module._load,express=require('express');const calls=[];let reject=false;
 const invoke=name=>async args=>{await new Promise(resolve=>setImmediate(resolve));calls.push({name,args});if(reject)throw Error('fixture unavailable');return{ok:true,name,...(name==='download'?{mime:'image/svg+xml',abs:'/fixture/raw.svg',body_base64:Buffer.from('<svg onload=alert(1)></svg>').toString('base64')}:{})};};
 Module._load=function(request,parent,main){
  if(request.endsWith('/agents/email/tools/index.js'))return Object.fromEntries(['send','read_inbox','summarize_thread','auto_reply'].map(n=>[n,invoke(n)]));
  if(request.endsWith('/agents/uploads/tools/index.js'))return {createUploadTools:({uploadRoot})=>{assert.ok(require('node:path').isAbsolute(uploadRoot));return {UPLOAD_ROOT:uploadRoot,...Object.fromEntries(['upload_avatar','upload_product_image','upload_return_evidence','upload_product_manual','download'].map(n=>[n,invoke(n)]))};}};
  if(['sqlite3','better-sqlite3'].includes(request)||/\/authDb$/.test(request))throw Error('Real database forbidden');
  return original.call(this,request,parent,main);
 };
 const files=['../server/routes/secureshop/email','../server/routes/secureshop/uploads'].map(require.resolve);files.forEach(f=>delete require.cache[f]);let server;
 try{
  const app=express();app.use(express.json());for(const file of files)app.use(require(file)());
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});const base=`http://127.0.0.1:${server.address().port}`;
  const request=(url,body)=>fetch(base+url,body===undefined?{}:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  for(const [url,body,name] of [['/email/send',{subject:'raw\r\nBcc: fixture'},'send'],['/email/inbox/42',undefined,'read_inbox'],['/email/thread/4',undefined,'summarize_thread'],['/email/auto-reply/4',{from:'fixture'},'auto_reply']])assert.equal((await(await request(url,body)).json()).name,name);
  assert.equal(calls[0].args.subject,'raw\r\nBcc: fixture');assert.equal(calls[1].args.user_id,42);
  for(const kind of ['avatar','product_image','return_evidence','product_manual']){
   const r=await request('/uploads',{kind,scope_id:7,filename:'....//raw.svg',mime:'image/svg+xml',file_bytes_base64:'PHN2Zz4='});assert.equal((await r.json()).name,'upload_'+kind);
  }
  assert.equal(calls.at(-1).args.filename,'....//raw.svg');
  const download=await request('/uploads/download?id=7');assert.equal(download.status,200);assert.match(download.headers.get('content-type'),/image\/svg\+xml/);assert.equal(download.headers.get('content-disposition'),'inline; filename="raw.svg"');assert.equal(download.headers.get('x-content-type-options'),null);assert.equal(await download.text(),'<svg onload=alert(1)></svg>');
  reject=true;
  for(const [url,body] of [['/email/send',{}],['/email/inbox/42',undefined],['/uploads',{file_bytes_base64:'AA=='}],['/uploads/download?id=7',undefined]]){const r=await request(url,body);assert.equal(r.status,500);assert.deepEqual(await r.json(),{ok:false,error:'fixture unavailable'});}
 }finally{if(server)await new Promise(resolve=>server.close(resolve));Module._load=original;files.forEach(f=>delete require.cache[f]);}
});

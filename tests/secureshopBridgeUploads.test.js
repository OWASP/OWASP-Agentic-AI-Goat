'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fields = {kind:'product_manual',scope_id:'7',mime:'text/html',public:'true'};
const input = () => ({file:new Blob(['<script>synthetic()</script>'],{type:'text/html'}),filename:'../../lesson.html',fields});

test('typed upload preserves crafted filename, MIME, fields and exact bytes through real MessagePorts', async () => {
  const { compileBridgeOperation } = await import('../client/src/pages/secureshop/bridge/compiler.mjs');
  const { createHostTransport,createFrameTransport } = await import('../client/src/pages/secureshop/bridge/transport.mjs');
  const channel=new MessageChannel();let captured;
  const host=createHostTransport({port:channel.port1,compileOperation:compileBridgeOperation,origin:'http://localhost:3000',getLaunchBearer:()=> 'a'.repeat(43),fetchImpl:async(url,init)=>{captured={url,init};return new Response('{"ok":true}',{headers:{'content-type':'application/json'}});}});
  const frame=createFrameTransport({port:channel.port2});
  try {
    assert.deepEqual(await (await frame.request('uploads.create',input())).json(),{ok:true});
    assert.equal(captured.url,'http://localhost:3000/api/secureshop/uploads');assert.equal(captured.init.headers.has('content-type'),false);assert.equal(captured.init.credentials,'omit');
    const form=captured.init.body;assert.ok(form instanceof FormData);
    assert.equal(form.get('file').name,'../../lesson.html');assert.equal(form.get('file').type,'text/html');assert.equal(await form.get('file').text(),'<script>synthetic()</script>');
    for (const [key,value] of Object.entries(fields)) assert.equal(form.get(key),value);
  } finally {frame.close();host.close();}
});

test('upload rejects expanded fields, duplicate parts, forged blobs and size overflow', async () => {
  const {compileUpload,encodeUploadFormData,MAX_UPLOAD_BYTES}=await import('../client/src/pages/secureshop/bridge/uploads.mjs');
  for(const value of [{...input(),url:'http://evil.example'}, {...input(),fields:{...fields,platformOwnerId:'7'}}, {...input(),file:{size:1}}, {...input(),file:new Blob([new Uint8Array(MAX_UPLOAD_BYTES+1)])}]) assert.throws(()=>compileUpload(value));
  const form=new FormData();form.append('file',input().file,'lesson.html');form.append('file',input().file,'extra.html');for(const [k,v] of Object.entries(fields))form.append(k,v);
  assert.throws(()=>encodeUploadFormData(form));
});

test('existing UploadZone FormData fetch becomes typed operation without filename or byte rewriting', async () => {
  const {createBridgeFetch}=await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');let captured;
  const fetch=createBridgeFetch({origin:'http://localhost:3000',bridge:{request(...args){captured=args;return Promise.resolve(new Response('{}'));}}});
  const form=new FormData();form.append('file',input().file,'../../lesson.html');for(const [k,v] of Object.entries(fields))form.append(k,v);
  await fetch('/api/secureshop/uploads',{method:'POST',body:form});
  assert.equal(captured[0],'uploads.create');assert.equal(captured[1].filename,'../../lesson.html');assert.equal(await captured[1].file.text(),await input().file.text());
  await assert.rejects(fetch('/api/secureshop/uploads',{method:'POST',headers:{'content-type':'multipart/form-data; boundary=forged'},body:form}));
});

test('upload metadata bounds include Blob MIME and aggregate Unicode fields', async () => {
  const {compileUpload}=await import('../client/src/pages/secureshop/bridge/uploads.mjs');
  assert.throws(()=>compileUpload({...input(),file:new Blob([],{type:'a'.repeat(2000000)})}));
  assert.throws(()=>compileUpload({...input(),filename:'界'.repeat(4096),fields:Object.fromEntries(Object.keys(fields).map(key=>[key,'界'.repeat(4096)]))}));
  assert.equal(compileUpload(input()).body.file.type,'text/html');
});

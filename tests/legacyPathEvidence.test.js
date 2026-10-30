'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { didReadOutsideRoot } = require('../server/services/legacyPathEvidence');
test('legacy traversal evidence distinguishes actual boundary crossing from names and normalized paths', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-path-evidence-'));
  t.after(() => fs.rmSync(tmp, {recursive:true, force:true}));
  const root = path.join(tmp, 'lab'); fs.mkdirSync(root); fs.mkdirSync(path.join(root,'nested'));
  const inside = path.join(root,'admin-secret-config.txt'); fs.writeFileSync(inside,'fictional training data');
  const outside = path.join(tmp,'outside.txt'); fs.writeFileSync(outside,'isolated sibling fixture');
  assert.equal(didReadOutsideRoot(root,inside),false);
  assert.equal(didReadOutsideRoot(root,path.join(root,'nested','..','admin-secret-config.txt')),false);
  assert.equal(didReadOutsideRoot(root,path.join(root,'..','outside.txt')),true);
  fs.symlinkSync(outside,path.join(root,'linked.txt'));
  assert.equal(didReadOutsideRoot(root,path.join(root,'linked.txt')),true);
  assert.throws(() => didReadOutsideRoot(root,path.join(root,'missing.txt')), {code:'ENOENT'});
});

test('mounted lookup routes report traversal only for a read outside the root and retain authenticated audit ownership', async t => {
  const express = require('express');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-path-route-'));
  t.after(() => fs.rmSync(tmp, {recursive:true, force:true}));
  const root = path.join(tmp,'lab'); fs.mkdirSync(root);
  fs.writeFileSync(path.join(root,'secret-admin-config.txt'),'FLAG{inside_fixture}');
  fs.writeFileSync(path.join(tmp,'outside.txt'),'FLAG{outside_fixture}');
  let selected = 'secret-admin-config.txt'; const logs=[];
  const store = {getFilePathByReference:async()=>selected,getTemplateByName:async()=>null,
    logExploitation:async value=>logs.push(value)};
  const router = require('../server/routes/postgres/sensitiveLookup')({store,filesDir:root,
    aiService:{processSensitiveInfoRequest:async()=>({response:'controlled model fixture',provider:'mock',model:'mock'})},
    authenticate:(req,res,next)=>{req.user={id:'actual-owner'};next();},
    coordinator:{run:async(owner,input,fn)=>{assert.equal(owner,'actual-owner');return fn({check:async()=>{}});}}});
  const app=express();app.use(express.json());app.use(router);
  const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  for(const target of ['secret-admin-config.txt','../outside.txt']){
    selected=target;const escaped=target.startsWith('../');
    for(const [route,body] of [['path-traversal',{referenceKey:'fixture'}],['combined-attack',{referenceKey:'fixture'}],['ai-chat',{message:'read file'}]]){
      const response=await fetch(`http://127.0.0.1:${server.address().port}/mysql/${route}`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,userId:'forged-owner'})});
      assert.equal(response.status,200);const data=await response.json();
      assert.equal(data.exploited,route==='combined-attack'?false:escaped,route+' '+target);
      // Combined credit requires both SSI and traversal, not a file escape alone.
      if(route==='combined-attack')assert.equal(data.pathTraversal.occurred,escaped);
    }
  }
  assert.ok(logs.length>=4);assert.ok(logs.every(row=>row.userId==='actual-owner'));
  assert.ok(logs.some(row=>row.success===false));assert.ok(logs.some(row=>row.success===true));
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createHash } = require('node:crypto');
const { createSecureShopSvgAssetBrowserQualification } = require('../../server/services/secureshopSvgAssetBrowserQualification');
const sha = value => createHash('sha256').update(value).digest('hex');
const marker = 'dvaia-v08-actual-6d379be0';
const positive = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><script>console.log('${marker}')</script></svg>`);
const noScript = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" onload="console.log('${marker}')"/>`);
const foreign = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><script>if(false){console.log('${marker}')}</script><script>console.log('dvaia-v08-'+'actual-6d379be0')</script></svg>`);
const changed = Buffer.from(positive); changed[changed.length - 2] ^= 1;
const assets = new Map([['positive',positive],['no-script',noScript],['foreign-script',foreign],['changed',changed]]);
function expected(bytes, bodySha256=sha(bytes)){return{byteCount:bytes.length,bodySha256,contentType:'image/svg+xml',contentSecurityPolicy:'sandbox allow-scripts',marker};}
test('installed Chrome qualifies only exact covered SVG script and same-script effect', {timeout:60000}, async t => {
  const requests=[];
  const server=http.createServer((req,res)=>{
    requests.push({url:req.url,cookie:req.headers.cookie||null,authorization:req.headers.authorization||null,origin:req.headers.origin||null});
    const name=/^\/assets\/([a-z-]+)$/.exec(req.url||'')?.[1],body=assets.get(name);
    if(!body){res.statusCode=404;return res.end();}
    res.statusCode=200;res.setHeader('Content-Type','image/svg+xml');res.setHeader('Content-Security-Policy','sandbox allow-scripts');res.setHeader('Cross-Origin-Resource-Policy','cross-origin');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-store');res.end(body);
  });
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'::1',resolve));
  const address=server.address(),origin=`http://[::1]:${address.port}`;
  const qualification=createSecureShopSvgAssetBrowserQualification({assetOrigin:origin,timeoutMs:8000,startupTimeoutMs:30000,idleCloseMs:1000,retirementTimeoutMs:5000});
  t.after(async()=>{try{await qualification.close();}finally{await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));}});
  const run=(name,expectedValue)=>qualification.qualify({assetUrl:`${origin}/assets/${name}`,expected:expectedValue},{signal:AbortSignal.timeout(30000)});
  const pass=await run('positive',expected(positive));
  assert.equal(pass.executed,true);assert.equal(pass.asset.bodySha256,sha(positive));assert.equal(pass.script.consoleStackJoined,true);
  for(const [name,expectation,reason] of [
    ['no-script',expected(noScript),'svg_inline_script_unavailable'],
    ['foreign-script',expected(foreign),'svg_effect_not_observed'],
    ['changed',expected(changed,sha(positive)),'asset_bytes_mismatch'],
  ]){const result=await run(name,expectation);assert.equal(result.executed,false,JSON.stringify(result));assert.equal(result.reason,reason);}
  assert.equal(requests.length,4);for(const request of requests)assert.deepEqual({...request,url:undefined},{url:undefined,cookie:null,authorization:null,origin:null});
});

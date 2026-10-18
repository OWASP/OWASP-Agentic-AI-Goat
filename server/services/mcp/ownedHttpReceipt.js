'use strict';
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const {canonicalDigest}=require('../../../sidecars/sandbox-runner/owned-http/canonical');
const bytes=fs.readFileSync(path.resolve(__dirname,'../../../sidecars/sandbox-runner/owned-http/network-manifest.json'));
const manifest=JSON.parse(bytes);const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const attestations=['zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors','udpExternalRouteDenied','ipv6ExternalRouteDenied'];
function verifyOwnedHttpReceipt(receipt,identity){
 const fail=()=>{throw Object.assign(Error('HTTP_RECEIPT_INVALID'),{code:'HTTP_RECEIPT_INVALID'});};
 if(!receipt||receipt.version!=='mcp-owned-http-operation.v1'||receipt.requestDigest!==canonicalDigest(identity)
  ||canonicalDigest(receipt.identity)!==canonicalDigest(identity)||receipt.manifestSha256!==sha(bytes)
  ||!/^[a-f0-9]{64}$/.test(receipt.canarySha256||'')||Buffer.byteLength(JSON.stringify(receipt))>131072)fail();
 const result=receipt.result;
 if(!result||result.version!==1||result.mode!==identity.mode||result.originalUrlSha256!==sha(identity.url)
  ||result.originalUrlBytes!==Buffer.byteLength(identity.url)||!['completed','failed'].includes(result.status)
  ||!attestations.every(key=>result.isolationAttestation?.[key]===true)
  ||!Array.isArray(result.hops)||result.hops.length>4||!Array.isArray(result.hits)||result.hits.length>16
  ||(result.status==='completed'&&!result.hops.length))fail();
 for(const hit of result.hits){const target=manifest.listeners.find(item=>item.id===hit.listener);
  if(!target||hit.localAddress!==target.address||hit.localPort!==target.port||hit.method!=='GET'||!/^[a-f0-9]{64}$/.test(hit.responseSha256||''))fail();}
 for(const [index,hop] of result.hops.entries()){
  if(typeof hop.body!=='string'||Buffer.byteLength(hop.body)>32768)fail();
  let url;try{url=new URL(hop.effectiveUrl);}catch{fail();}
  let expected;try{expected=index===0?new URL(identity.url).href:new URL(result.hops[index-1].location,result.hops[index-1].effectiveUrl).href;}catch{fail();}
  if(url.href!==expected||url.protocol!=='http:'||url.username||url.password)fail();
  if(identity.mode==='fixed'&&!(url.hostname==='benign.training'&&hop.resolvedAddress==='192.0.2.10'&&hop.port===80))fail();
  const hit=result.hits.find(item=>item.localAddress===hop.resolvedAddress&&item.localPort===hop.port&&item.host===url.host&&item.path===url.pathname+url.search&&item.status===hop.status&&item.responseSha256===sha(hop.body));
  if(!hit)fail();const target=manifest.listeners.find(item=>item.id===hit.listener);
  if(hop.status===200&&target.sensitive){let body;try{body=JSON.parse(hop.body);}catch{fail();}if(body.service!==target.id||typeof body.canary!=='string'||sha(body.canary)!==receipt.canarySha256)fail();}
 }
 return receipt;
}
module.exports={verifyOwnedHttpReceipt};

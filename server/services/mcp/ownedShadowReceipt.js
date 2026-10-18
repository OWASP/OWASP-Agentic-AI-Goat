'use strict';
const crypto=require('node:crypto');const {canonicalDigest}=require('../../../sidecars/sandbox-runner/owned-http/canonical');
const {peers}=require('../../../sidecars/sandbox-runner/owned-shadow/contract');
const fail=()=>{throw Object.assign(Error('SHADOW_RECEIPT_INVALID'),{code:'SHADOW_RECEIPT_INVALID'});};
function verifyOwnedShadowReceipt(receipt,identity,registration=null){
 const q=identity?.request,b=identity?.binding,r=receipt?.result;
 if(receipt?.version==='owned-shadow-denial.v1'){if(!q||q.action!=='register'||q.mode!=='fixed'||q.endpoint!=='http://10.0.1.100:8080/mcp'||receipt.action!=='register'||receipt.mode!==q.mode||receipt.endpoint!==q.endpoint||receipt.code!=='SHADOW_UNAPPROVED_PEER'||receipt.handshakeAttempted!==false||receipt.requestDigest!==canonicalDigest(identity)||canonicalDigest(receipt.binding)!==canonicalDigest(b)||['operationId','registrationId','runId','invocationId'].some(k=>receipt[k]!==q[k])||!['manifestSha256','runtimeDigest'].every(k=>/^[a-f0-9]{64}$/.test(receipt[k]||''))||Object.keys(receipt).sort().join(',')!==['version','requestDigest','binding','operationId','registrationId','runId','invocationId','action','mode','endpoint','code','handshakeAttempted','manifestSha256','runtimeDigest'].sort().join(','))fail();return receipt;}
if(!q||!b||!receipt||receipt.version!=='owned-shadow.v1'||receipt.requestDigest!==canonicalDigest(identity)||canonicalDigest(receipt.binding)!==canonicalDigest(b)||['operationId','registrationId','runId','invocationId','action'].some(k=>receipt[k]!==q[k])||Buffer.byteLength(JSON.stringify(receipt))>131072)fail();
 if(!r||r.version!==1||r.isolationAttested!==true||!Array.isArray(r.catalog)||r.catalog.length!==1||r.catalog[0].name!=='read_policy'||r.catalog[0].inputSchema?.type!=='object'||r.catalogDigest!==canonicalDigest(r.catalog)||r.identity?.name!=='policy-library'||r.identity.version!=='1.0.0')fail();
 const peer=peers.find(p=>p.endpoint===r.endpoint);if(!peer||r.peerId!==peer.id||r.approved!==(peer.id==='approved')||!['fixed','vuln'].includes(receipt.mode)||(receipt.mode==='fixed'&&!r.approved)||!['manifestSha256','runtimeDigest'].every(k=>/^[a-f0-9]{64}$/.test(receipt[k]||'')))fail();
 if(!receipt.sourceDigests||!['approved','rogue'].every(k=>/^[a-f0-9]{64}$/.test(receipt.sourceDigests[k]||''))||!Array.isArray(r.hits)||r.hits.length>16||r.hits.some(h=>h.peer!==peer.id||h.path!=='/mcp')||!['initialize','tools/list'].every(method=>r.hits.some(h=>h.method===method)))fail();
 if(q.action==='register'){if(r.endpoint!==q.endpoint||receipt.mode!==q.mode||r.result!==null||!Array.isArray(r.reads)||r.reads.length!==0||r.hits.some(h=>h.method==='tools/call'))fail();}
 else if(q.action==='invoke'){
  if(!registration||registration.registrationId!==q.registrationId||registration.action!=='register'||registration.result.endpoint!==r.endpoint||registration.result.catalogDigest!==r.catalogDigest||registration.runtimeDigest!==receipt.runtimeDigest||registration.mode!==receipt.mode||canonicalDigest(registration.binding)!==canonicalDigest(b)||q.remoteName!=='read_policy'||q.args?.section!=='policy'||Object.keys(q.args).length!==1)fail();
  if(!r.hits.some(h=>h.method==='tools/call')||r.result?.isError||r.result?.content?.length!==1||r.result.content[0].type!=='text'||typeof r.result.content[0].text!=='string'||r.reads?.length!==1||r.reads[0].peer!==peer.id)fail();
  const sha=crypto.createHash('sha256').update(r.result.content[0].text).digest('hex');if(sha!==r.reads[0].sourceSha256||sha!==receipt.sourceDigests[peer.id])fail();
 }else fail();return receipt;
}
module.exports={verifyOwnedShadowReceipt};

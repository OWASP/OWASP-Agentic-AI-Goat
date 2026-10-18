'use strict';
// Controlled unit/native repository fixture, never actual socket/model proof.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {canonicalDigest}=require('../../sidecars/sandbox-runner/owned-http/canonical');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
function receiptFor(identity){const canary='a'.repeat(64),body=JSON.stringify({service:'metadata',canary}),url=new URL(identity.url);
 return {version:'mcp-owned-http-operation.v1',identity,requestDigest:canonicalDigest(identity),manifestSha256:hash(fs.readFileSync(path.resolve(__dirname,'../../sidecars/sandbox-runner/owned-http/network-manifest.json'))),canarySha256:hash(canary),result:{version:1,mode:identity.mode,status:'completed',originalUrlSha256:hash(identity.url),originalUrlBytes:Buffer.byteLength(identity.url),isolationAttestation:Object.fromEntries(['zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors','udpExternalRouteDenied','ipv6ExternalRouteDenied'].map(key=>[key,true])),hops:[{effectiveUrl:url.href,resolvedAddress:'169.254.169.254',port:80,status:200,location:null,body}],hits:[{listener:'metadata',localAddress:'169.254.169.254',localPort:80,method:'GET',host:url.host,path:url.pathname+url.search,status:200,responseSha256:hash(body)}]}};
}
module.exports={receiptFor};

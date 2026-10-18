'use strict';
const crypto=require('node:crypto');
const peers=Object.freeze([{id:'approved',endpoint:'http://192.0.2.10/mcp',fd:6},{id:'rogue',endpoint:'http://10.0.1.100:8080/mcp',fd:4}]);
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
function error(code){return Object.assign(Error(code),{code});}
function validate(input){
 if(!input||!['register','invoke'].includes(input.action)||!['vuln','fixed'].includes(input.mode)||typeof input.endpoint!=='string'||Buffer.byteLength(input.endpoint)>2048)throw error('SHADOW_INPUT_INVALID');
 if(!input.sources||Object.keys(input.sources).sort().join(',')!=='approved,rogue'||Object.values(input.sources).some(v=>typeof v!=='string'||Buffer.byteLength(v)>16384))throw error('SHADOW_SOURCE_INVALID');
 if(input.action==='invoke'&&(!/^[a-f0-9]{64}$/.test(input.expectedCatalogDigest||'')||input.remoteName!=='read_policy'||!input.args||Object.keys(input.args).join(',')!=='section'||input.args.section!=='policy'))throw error('SHADOW_INVOCATION_INVALID');
 const peer=peers.find(p=>p.endpoint===input.endpoint);if(!peer)throw error('SHADOW_ENDPOINT_DENIED');
 if(input.mode==='fixed'&&peer.id!=='approved')throw error('SHADOW_UNAPPROVED_PEER');return peer;
}
module.exports={peers,validate};

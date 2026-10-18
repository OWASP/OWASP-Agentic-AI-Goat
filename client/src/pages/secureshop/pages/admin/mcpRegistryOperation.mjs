import { shopStorage, flushShopStorage, SHOP_MCP_REGISTRY_KEY } from '../../utils/shopStorage.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const VERSION=/^(0|[1-9][0-9]{0,15})$/;
export function administration(value){
 if(!value||value.ready!==true)return null;
 if(Object.keys(value).sort().join(',')!=='ready,scopeKey,version'||typeof value.scopeKey!=='string'||! /^[a-f0-9]{64}$/.test(value.scopeKey)||typeof value.version!=='string'||!VERSION.test(value.version)||BigInt(value.version)>9007199254740991n)throw Error('Invalid registry administration');
 return Object.freeze({...value});
}
function normalized(request){
 if(!request||request.version!==1||!UUID.test(request.operationId||'')||typeof request.expectedVersion!=='string'||!VERSION.test(request.expectedVersion)||BigInt(request.expectedVersion)>=9007199254740991n)throw Error('Invalid saved registry operation');
 const base={version:1,action:request.action,operationId:request.operationId,expectedVersion:request.expectedVersion};
 const text=(s,max)=>typeof s==='string'&&s.trim()&&!s.includes('\0')&&s.isWellFormed()&&new TextEncoder().encode(s).length<=max;
 let value;
 if(request.action==='register'){
  if(!text(request.name,256)||!['sse','streamable-http','stdio'].includes(request.transport))throw Error('Invalid registry registration');
  if(request.transport==='stdio'){if(request.url!==''||!text(request.stdio_cmd,4096))throw Error('Invalid registry command');}
  else if(request.stdio_cmd!==''||!validUrl(request.url))throw Error('Invalid registry URL');
  value={...base,name:request.name,transport:request.transport,url:request.url,stdio_cmd:request.stdio_cmd};
 }else if(request.action==='import'){if(!validUrl(request.xml_url))throw Error('Invalid manifest URL');value={...base,xml_url:request.xml_url};}
 else if(request.action==='retire'){if(!text(request.name,256))throw Error('Invalid registry name');value={...base,name:request.name};}
 else throw Error('Invalid registry action');
 if(Object.keys(value).sort().join(',')!==Object.keys(request).sort().join(','))throw Error('Invalid registry fields');
 return Object.freeze(value);
}
function validUrl(s){try{return typeof s==='string'&&s.isWellFormed()&&!s.includes('\0')&&new TextEncoder().encode(s).length<=4096&&['http:','https:'].includes(new URL(s).protocol);}catch{return false;}}
async function digest(value){const bytes=await globalThis.crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(value)));return Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');}
export const normalizeSavedRegistryRequest=normalized;
export const registryRequestHash=digest;
export async function createOperation(admin,action,fields){const a=administration(admin);if(!a)throw Error('Registry writes are unavailable');const request=normalized({version:1,action,operationId:globalThis.crypto.randomUUID(),expectedVersion:a.version,...fields});return Object.freeze({scopeKey:a.scopeKey,request,requestSha256:await digest(request)});}
const samePending=(left,right)=>!!left&&!!right&&left.scopeKey===right.scopeKey
 &&left.requestSha256===right.requestSha256
 &&JSON.stringify(left.request)===JSON.stringify(right.request);
function decodePending(raw){
 if(raw===null)return null;
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>8192)throw Error('Invalid saved registry operation');
 let value;try{value=JSON.parse(raw);}catch{throw Error('Invalid saved registry operation');}
 if(!value||Object.getPrototypeOf(value)!==Object.prototype
  ||Object.keys(value).sort().join(',')!=='request,requestSha256,scopeKey'
  ||typeof value.scopeKey!=='string'||! /^[a-f0-9]{64}$/.test(value.scopeKey)
  ||typeof value.requestSha256!=='string'||! /^[a-f0-9]{64}$/.test(value.requestSha256))throw Error('Invalid saved registry operation');
 return Object.freeze({...value,request:normalized(value.request)});
}
export async function readAnyPending(){
 const value=decodePending(shopStorage.getItem(SHOP_MCP_REGISTRY_KEY));
 if(value&&await digest(value.request)!==value.requestSha256)throw Error('Invalid saved registry operation');
 return value;
}
export async function readPending(scopeKey){
 const value=await readAnyPending();return value?.scopeKey===scopeKey?value:null;
}
export function assertPendingCurrent(operation){
 const current=decodePending(shopStorage.getItem(SHOP_MCP_REGISTRY_KEY));
 if(!samePending(current,operation))throw Error('Registry recovery authority changed');
 return current;
}
export async function savePending(value,current=()=>true){
 const request=normalized(value?.request);
 const saved=decodePending(JSON.stringify({...value,request}));
 if(await digest(request)!==saved.requestSha256)throw Error('Invalid saved registry operation');
 if(!current())throw Error('Registry recovery authority changed');
 if(shopStorage.getItem(SHOP_MCP_REGISTRY_KEY)!==null)throw Error('Check the saved registry operation before another change');
 shopStorage.setItem(SHOP_MCP_REGISTRY_KEY,JSON.stringify(saved));
 await flushShopStorage();
 if(!current())throw Error('Registry recovery authority changed');
 assertPendingCurrent(saved);
 return saved;
}
export async function clearPending(operation,current=()=>true){
 if(!current())throw Error('Registry recovery authority changed');
 assertPendingCurrent(operation);
 try{
  shopStorage.removeItem(SHOP_MCP_REGISTRY_KEY);await flushShopStorage();
  if(!current())throw Error('Registry recovery authority changed');
  if(shopStorage.getItem(SHOP_MCP_REGISTRY_KEY)!==null)throw Error('Registry recovery authority changed');
 }catch(error){
  if(current())try{
   if(shopStorage.getItem(SHOP_MCP_REGISTRY_KEY)===null){
    shopStorage.setItem(SHOP_MCP_REGISTRY_KEY,JSON.stringify(operation));await flushShopStorage();
   }
  }catch{/* The caller retains the unresolved operation. */}
  throw error;
 }
}
export function mutationAddress(operation){const r=operation.request;return r.action==='retire'?{url:`/api/secureshop/admin/mcp/${encodeURIComponent(r.name)}`,method:'DELETE'}:{url:`/api/secureshop/admin/mcp/${r.action==='register'?'register':'import-manifest'}`,method:'POST'};}
export function verifyReceipt(value,operation){
 if(!value||value.version!=='secureshop-owned-mcp-registry.v1'||value.operationId!==operation.request.operationId||value.action!==operation.request.action||value.requestSha256!==operation.requestSha256||!['admitted','completed','failed','unknown'].includes(value.state))throw Error('Registry acknowledgement could not be verified');
 if(value.state==='completed'&&(value.ok!==true||value.registryVersion!==String(BigInt(operation.request.expectedVersion)+1n)||!Array.isArray(value.changes)||value.changes.length<1||value.changes.length>32||new Set(value.changes.map(c=>c?.name)).size!==value.changes.length||value.changes.some(c=>!c||typeof c.name!=='string'||c.action!==operation.request.action)||(operation.request.action!=='import'&&(value.changes.length!==1||value.changes[0].name!==operation.request.name))))throw Error('Registry completion could not be verified');
 return value;
}

// This is a display projection of an already verified, saved import receipt.
// The worker may repeat the same read for each imported server; count it once.
export async function verifiedImportEntityReads(receipt){
 if(receipt?.state!=='completed'||receipt.action!=='import')return [];
 const invalid=()=>{throw Error('Saved manifest entity read could not be verified');};
 if(!Array.isArray(receipt.changes)||receipt.changes.length<1||receipt.changes.length>32)invalid();
 const byPath=new Map(),encoder=new TextEncoder();
 let observedMode=null,missingEffect=false;
 for(const change of receipt.changes){
  const effect=change?.effect,reads=effect?.entityReads;
  if(effect===undefined)missingEffect=true;
  if(effect!==undefined&&(effect?.isolation!=='owned-mcp-registry-v1'
   ||!['vuln','fixed'].includes(effect.mode)))invalid();
  if(effect!==undefined){
   if(observedMode!==null&&observedMode!==effect.mode)invalid();
   observedMode=effect.mode;
  }
  if(reads===undefined)continue; // Historical receipts may predate read reporting.
  if(!Array.isArray(reads)||reads.length>8)invalid();
  if(effect.mode==='fixed'&&reads.length)invalid();
  for(const read of reads){
   if(!read||Object.keys(read).sort().join(',')!=='bytes,path,sha256,value'
    ||typeof read.path!=='string'||!read.path.startsWith('/owned-mcp-files/')
    ||read.path.slice('/owned-mcp-files/'.length).split('/')
      .some(part=>!part||part==='.'||part==='..')
    ||typeof read.value!=='string'||!read.value.isWellFormed()
    ||!Number.isSafeInteger(read.bytes)||read.bytes<0||read.bytes>16384
    ||!/^[a-f0-9]{64}$/.test(read.sha256||''))invalid();
   const bytes=encoder.encode(read.value);
   if(bytes.length!==read.bytes)invalid();
   const actual=Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',bytes)),
    value=>value.toString(16).padStart(2,'0')).join('');
   if(actual!==read.sha256)invalid();
   const prior=byPath.get(read.path);
   if(prior&&(prior.sha256!==read.sha256||prior.bytes!==read.bytes
    ||prior.value!==read.value))invalid();
   byPath.set(read.path,Object.freeze({path:read.path,sha256:read.sha256,
    bytes:read.bytes,value:read.value}));
   if(byPath.size>8)invalid();
  }
 }
 if(missingEffect&&byPath.size)invalid();
 if([...byPath.values()].reduce((sum,read)=>sum+read.bytes,0)>131072)invalid();
 return Object.freeze([...byPath.values()]);
}

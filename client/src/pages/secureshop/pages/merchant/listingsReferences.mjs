import { listingsChatSource } from '../../utils/merchantListingsSetup.mjs';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const actions=['rewrite','import','optimize','save','template'];
const own=(value,key)=>Object.prototype.hasOwnProperty.call(value,key);
const plain=value=>value&&Object.getPrototypeOf(value)===Object.prototype;

function checkRow(kind,row,scopeKey){
 const keys=kind==='assessment'
  ?['scopeKey','digest','requestId','rewriteOperationId','saveOperationId',...(row?.retryRequestId!==undefined||row?.evaluationId!==undefined?['retryRequestId','evaluationId']:[])]
  :['scopeKey','digest','operationId',...(kind==='template'?['productId']:[]),...(row?.chatSource!==undefined?['chatSource']:[]),...(row?.rewriteOperationId!==undefined?['rewriteOperationId']:[])];
 if(!plain(row)||Object.keys(row).sort().join(',')!==keys.sort().join(',')
  ||keys.some(key=>key!=='productId'&&key!=='chatSource'&&typeof row[key]!=='string')||!SHA.test(row.scopeKey)||!SHA.test(row.digest)
  ||(kind==='template'&&(!Number.isSafeInteger(row.productId)||row.productId<1||row.productId>2147483647))
  ||(scopeKey&&row.scopeKey!==scopeKey)||keys.filter(key=>key.endsWith('Id')&&key!=='productId').some(key=>!UUID.test(row[key])))throw Error('Invalid Listings reference');
 if(row.rewriteOperationId!==undefined&&!['save','assessment'].includes(kind))throw Error('Invalid Listings save reference');
 if(row.chatSource!==undefined){if(!['rewrite','import','optimize','save'].includes(kind))throw Error('Invalid Listings chat reference');listingsChatSource(row.chatSource);}
}

function checkGroup(group,scopeKey){
 if(!plain(group)||Object.keys(group).some(key=>!['scopeKey',...actions,'assessment'].includes(key))
  ||(scopeKey&&own(group,'scopeKey')&&group.scopeKey!==scopeKey)||(own(group,'scopeKey')&&!SHA.test(group.scopeKey)))throw Error('Invalid Listings references');
 for(const action of actions)if(own(group,action))checkRow(action,group[action],scopeKey);
 if(own(group,'assessment')){
  if(!Array.isArray(group.assessment)||group.assessment.length>8)throw Error('Invalid Listings references');
  const ids=new Set();
  for(const row of group.assessment){checkRow('assessment',row,scopeKey);if(ids.has(row.requestId))throw Error('Duplicate Listings reference');ids.add(row.requestId);}
 }
}

export function decodeListingsReferences(raw){
 if(raw===null)return {};
 if(typeof raw!=='string'||new TextEncoder().encode(raw).length>8192)throw Error('Listings references exceed limit');
 const value=JSON.parse(raw);
 if(!plain(value)||Object.keys(value).some(key=>![...actions,'assessment','retained'].includes(key)))throw Error('Invalid Listings references');
 const {retained:ignored,...active}=value;
 checkGroup(active);
 if(own(value,'retained')){
  if(!Array.isArray(value.retained)||value.retained.length>8)throw Error('Listings reference capacity reached');
  const scopes=new Set();
  for(const group of value.retained){
   if(!plain(group)||!SHA.test(group.scopeKey)||scopes.has(group.scopeKey))throw Error('Invalid Listings references');
   scopes.add(group.scopeKey);checkGroup(group,group.scopeKey);
  }
 }
 groups(value);
 return value;
}

function groups(value){
 const result=new Map();
 const add=(kind,row)=>{
  const group=result.get(row.scopeKey)||{scopeKey:row.scopeKey};
  if(kind==='assessment')group.assessment=[...(group.assessment||[]),row];
  else if(own(group,kind))throw Error('Duplicate Listings reference');
  else group[kind]=row;
  result.set(row.scopeKey,group);
 };
 for(const action of actions)if(value[action])add(action,value[action]);
 for(const row of value.assessment||[])add('assessment',row);
 for(const group of value.retained||[]){
  for(const action of actions)if(group[action])add(action,group[action]);
  for(const row of group.assessment||[])add('assessment',row);
 }
 if(result.size>8)throw Error('Listings reference capacity reached');
 for(const group of result.values())checkGroup(group,group.scopeKey);
 return result;
}

export function listingsForScope(value,scopeKey){
 if(!SHA.test(scopeKey))throw Error('Invalid Listings scope');
 const group=groups(value).get(scopeKey);
 if(!group)return {};
 const {scopeKey:ignored,...entries}=group;
 return entries;
}

export function replaceListingsScope(value,scopeKey,entries){
 if(!SHA.test(scopeKey)||!plain(entries)||Object.keys(entries).some(key=>![...actions,'assessment'].includes(key)))throw Error('Invalid Listings scope');
 checkGroup(entries,scopeKey);
 const all=groups(value);
 if(Object.keys(entries).length)all.set(scopeKey,{scopeKey,...entries});
 else all.delete(scopeKey);
 if(all.size>8)throw Error('Listings reference capacity reached');
 const current=all.get(scopeKey),retained=[...all.values()].filter(group=>group.scopeKey!==scopeKey);
 const output={...(current?listingsForScope({retained:[current]},scopeKey):{}),...(retained.length?{retained}:{})};
 decodeListingsReferences(JSON.stringify(output));
 return output;
}

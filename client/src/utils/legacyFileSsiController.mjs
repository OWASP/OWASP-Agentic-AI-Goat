import {projectLegacyFileSsiSnapshot} from './legacyFileSsiSnapshot.mjs';
const BASE='/api/sensitive-info';
export function createLegacyFileSsiController({http,operationId=()=>crypto.randomUUID()}={}){
 if(typeof http?.get!=='function'||typeof http?.post!=='function')throw new TypeError('Authenticated HTTP client required');
 let pendingReset=null;
 return Object.freeze({
  async snapshot({signal}={}){const [state,mode]=await Promise.all([http.get(`${BASE}/canonical-agent/state`,{signal}),http.get(`${BASE}/canonical-agent/mode`,{signal})]);return projectLegacyFileSsiSnapshot(state.data.challenges,state.data.content,mode.data);},
  async attempt({objectiveId,input,signal}){
   const manual={path_traversal:['file/read',{filename:input}],ssi_injection:['template/render',{template:input}],combined_traversal_ssi:['document/process',{documentPath:input,processSSI:true}]};
   const chosen=manual[objectiveId]||(['ai_assisted_path_traversal','ai_assisted_ssi'].includes(objectiveId)?['canonical-agent/chat',{message:input}]:null);
   if(!chosen)throw new TypeError('Unknown file/SSI objective');
   const {data}=await http.post(`${BASE}/${chosen[0]}`,chosen[1],{signal});return data;
  },
  async setMode({mode,signal}={}){if(!['vuln','fixed'].includes(mode))throw new TypeError('Canonical File and SSI mode required');const {data}=await http.post(`${BASE}/canonical-agent/mode`,{mode},{signal});return data;},
  async reset({signal}={}){pendingReset ||= operationId();const {data}=await http.post(`${BASE}/canonical-agent/reset`,{},{headers:{'x-reset-operation-id':pendingReset},signal});pendingReset=null;return data;},
 });
}

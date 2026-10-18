'use strict';
const path=require('node:path');
const {findChallengeFlag}=require('../config/legacySensitiveFlags');
function fileBoundary(target,publicRoot,realpath=require('node:fs').realpathSync){
 try{
  const resolvedTarget=realpath(target),resolvedPublicRoot=realpath(publicRoot);
  const relative=path.relative(resolvedPublicRoot,resolvedTarget);
  const outside=relative==='..'||relative.startsWith(`..${path.sep}`)||path.isAbsolute(relative);
  return {resolvedTarget,publicRoot:resolvedPublicRoot,outsidePublic:outside};
 }catch{return {resolvedTarget:null,publicRoot:null,outsidePublic:false};}
}
function observedFacts(id,result,{realModel=false}={}){
 const usesSsi=['ssi_injection','combined_traversal_ssi','ai_assisted_ssi'].includes(id);
 const content=usesSsi?result.rendered:result.content;
 const flag=findChallengeFlag(content);
 return {observed_effect:usesSsi?typeof result.original==='string'&&typeof content==='string'&&content!==result.original&&/<!--#/.test(result.original)&&(id==='ai_assisted_ssi'||result.ssiSucceeded===true):typeof content==='string',
  protected_path:result.boundary?.outsidePublic===true,
  known_flag:Boolean(flag)&&(id!=='ai_assisted_ssi'||!String(result.original||'').includes(flag)),real_model:realModel===true};
}
module.exports={fileBoundary,observedFacts};

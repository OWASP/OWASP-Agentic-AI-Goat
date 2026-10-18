'use strict';
function fail(code){throw Object.assign(new Error(code),{code});}
function bindManifest(message,params){
 if(typeof message!=='string'||message.length>65536)fail('MANIFEST_BINDING_LIMIT');
 const objects=[];let start=-1,depth=0,quoted=false,escaped=false;
 for(let i=0;i<message.length;i++){
  const c=message[i];
  if(start<0){if(c==='{'){start=i;depth=1;}continue;}
  if(quoted){if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;continue;}
  if(c==='"')quoted=true;else if(c==='{')depth++;else if(c==='}'&&--depth===0){
   const raw=message.slice(start,i+1);let value;try{value=JSON.parse(raw);}catch{fail('INVALID_EXPLICIT_MANIFEST');}objects.push({raw,value});start=-1;
  }
 }
 if(start>=0)fail('INVALID_EXPLICIT_MANIFEST');
 if(objects.length>1)fail('AMBIGUOUS_EXPLICIT_MANIFEST');
 const candidate=objects[0];
 if(candidate)return {...params,manifest:candidate.raw};
 return params;
}
function bindingErrorResponse(error){if(error?.name==='AbortError'||!['MANIFEST_BINDING_LIMIT','INVALID_EXPLICIT_MANIFEST','AMBIGUOUS_EXPLICIT_MANIFEST'].includes(error?.code))return null;return {status:400,body:{error:'Provide one complete package.json manifest per request.',code:error.code}};}
module.exports={bindManifest,bindingErrorResponse};

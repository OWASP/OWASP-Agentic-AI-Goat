'use strict';
// Owned qualification only: retain the original startup diagnostic behavior while
// saving the underlying rejection inside the private disposable evidence root.
const fs=require('node:fs');
const path=require('node:path');
const target=process.env.DPI_PRIVATE_STARTUP_DIAGNOSTIC;
if(!target||!path.isAbsolute(target)||path.basename(target)!=='startup-private-error.json')throw Error('Private DPI startup diagnostic target required');
const diagnostic=require('../../server/services/applicationStartupDiagnostic');
const original=diagnostic.reportStartupDiagnostic;
diagnostic.reportStartupDiagnostic=(error,emit)=>{
 try{
  const seen=new Set();
  const project=(value,depth=0)=>{
   if(!value||typeof value!=='object'||seen.has(value)||depth>3)return null;
   seen.add(value);
   return {name:typeof value.name==='string'?value.name:null,code:typeof value.code==='string'?value.code:null,
    message:typeof value.message==='string'?value.message:null,stack:typeof value.stack==='string'?value.stack:null,
    cause:project(value.cause,depth+1),errors:Array.isArray(value.errors)?value.errors.slice(0,4).map(item=>project(item,depth+1)):[]};
  };
  fs.writeFileSync(target,JSON.stringify(project(error))+'\n',{mode:0o600,flag:'wx'});
 }catch{/* A diagnostic must never alter the application startup decision. */}
 return original(error,emit);
};

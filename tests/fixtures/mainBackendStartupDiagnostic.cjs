'use strict';
const path=require('node:path');
const SOURCE=path.resolve(__dirname,'../..');
const CODES=new Set(['CTF_DELIVERY_ACTIVATION_UNAVAILABLE','CTF_RUNTIME_UNAVAILABLE','INVALID_APPLICATION_DATA_ROOT','APPLICATION_INITIALIZATION_FAILED','APPLICATION_MAINTENANCE_CONTROL_UNAVAILABLE','APPLICATION_MAINTENANCE_DIRTY','INVALID_CONFIGURATION','DELETION_UNAVAILABLE','MODULE_NOT_FOUND']);
function diagnostic(error,source=SOURCE){
 const frames=[];
 for(const line of String(error?.stack||'').slice(0,16384).split('\n').slice(1,33)){
  const at=line.lastIndexOf(source+path.sep);if(at<0)continue;
  const match=line.slice(at+source.length+1).match(/^([A-Za-z0-9_./-]+\.(?:js|cjs|mjs)):(\d{1,7}):(\d{1,7})\)?$/);
  if(match&&!match[1].split('/').includes('..'))frames.push({file:match[1],line:Number(match[2]),column:Number(match[3])});
  if(frames.length===8)break;
 }
 return {type:'main-backend-startup-failure',stage:'startApplicationServer',name:['Error','TypeError','RangeError','AggregateError'].includes(error?.name)?error.name:'Error',code:CODES.has(error?.code)?error.code:'UNCLASSIFIED_STARTUP_ERROR',frames};
}
function wrap(original,emit){return function(...args){let result;try{result=original.apply(this,args);}catch(error){try{emit(diagnostic(error));}catch{}throw error;}return Promise.resolve(result).catch(error=>{try{emit(diagnostic(error));}catch{}throw error;});};}
function install(){
 if(process.env.PG_MAIN_BACKEND_STARTUP_DIAGNOSTIC!=='1')throw Error('Explicit fixture diagnostic required');
 const Module=require('node:module'),load=Module._load,target=path.join(SOURCE,'server/applicationServer.js');let wrapped=false;
 Module._load=function(request,parent,isMain){const value=load.apply(this,arguments);if(!wrapped&&Module._resolveFilename(request,parent,isMain)===target){wrapped=true;value.startApplicationServer=wrap(value.startApplicationServer,row=>process.stderr.write(JSON.stringify(row)+'\n'));}return value;};
}
module.exports={diagnostic,wrap};
if(process.env.PG_MAIN_BACKEND_STARTUP_DIAGNOSTIC==='1')install();

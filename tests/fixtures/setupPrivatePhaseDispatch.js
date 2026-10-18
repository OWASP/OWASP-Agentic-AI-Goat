'use strict';
const path=require('node:path');
function privatePhaseCommand(command,args,cwd,installation){
 if(command!==process.execPath||cwd!==installation||!path.isAbsolute(installation)||!Array.isArray(args)||args.length!==2||args[0]!=='server/database/sensitiveInfoFiles.js'||args[1]!=='--initialize-missing')throw Error('Unexpected private setup command');
 return [path.resolve(__dirname,'../../server/database/sensitiveInfoFiles.js'),'--initialize-missing'];
}
function privatePhaseFailure(error){
 const safeCode=value=>typeof value==='string'&&/^[A-Z0-9_]{1,80}$/.test(value);
 const result={type:'failure',code:safeCode(error?.code)?error.code:'SETUP_PHASE_FAILED',causes:(Array.isArray(error?.errors)?error.errors:[]).map(cause=>cause?.code).filter(safeCode).slice(0,16)};
 if(typeof error?.migration==='string'&&/^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(error.migration)&&error.migration.length<=128)result.migration=error.migration;
 return result;
}
function privateParentFailure(error){
 const projected=privatePhaseFailure({code:error?.code,errors:(Array.isArray(error?.causes)?error.causes:[]).map(code=>({code})),migration:error?.migration});
 const {type,...failure}=projected;return failure;
}
module.exports={privatePhaseCommand,privatePhaseFailure,privateParentFailure};

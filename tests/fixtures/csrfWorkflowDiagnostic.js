'use strict';
// Private fixture evidence only: retain bounded source locations, never exception
// messages, SQL, request content, cookies, URLs or environment values.
const fs=require('node:fs'),path=require('node:path');
function createDiagnostic({root,source}){
 let sequence=0;const stages=new Set(['executor','workflow','beginGrading','finalGrade']);
 return (stage,error)=>{if(!stages.has(stage))throw TypeError('Unknown diagnostic stage');if(sequence>=8)return;
  const frames=String(error?.stack||'').split('\n').slice(1,16).flatMap(line=>{const start=line.indexOf(source+path.sep);if(start<0)return[];const match=line.slice(start).match(/^(.*?):(\d+):(\d+)\)?$/);if(!match)return[];const file=path.relative(source,match[1]);if(!/^(server|tests)\/[A-Za-z0-9_./-]+$/.test(file)||file.includes('..'))return[];return[{file,line:Number(match[2]),column:Number(match[3])}];}).slice(0,8);
  const value={stage,name:['Error','TypeError','RangeError','AssertionError','AbortError','TimeoutError','DataCloneError'].includes(error?.name)?error.name:'OtherError',code:typeof error?.code==='string'&&/^[A-Z0-9_]{1,60}$/.test(error.code)?error.code:null,frames};
  fs.writeFileSync(path.join(root,'csrf-workflow-diagnostic-'+(++sequence)+'.json'),JSON.stringify(value,null,2),{mode:0o600});
 };
}
function instrumentWorkflowFactory(original,record,observeFinal){return options=>{const executor={...options.executor,execute:async args=>{try{return await options.executor.execute(args);}catch(error){record('executor',error);throw error;}}};const workflow=original({...options,executor});return Object.freeze({...workflow,run:async input=>{const args={...input};for(const stage of ['beginGrading','finalGrade'])if(typeof input[stage]==='function')args[stage]=async(...values)=>{try{const result=await input[stage](...values);if(stage==='finalGrade'&&observeFinal)observeFinal(values[0]);return result;}catch(error){record(stage,error);throw error;}};try{return await workflow.run(args);}catch(error){record('workflow',error);throw error;}}});};}
module.exports={createDiagnostic,instrumentWorkflowFactory};

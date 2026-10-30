'use strict';
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {FAMILIES}=require('../../db/postgres/map-agent-workshop-archive');
function input(family){
 const config=FAMILIES[family],stamp='2025-01-02 03:04:05.123456';
 const progress={id:17,user_id:'0007',objective_id:family==='finflow'?'tool_enum':'clean_request',...(family==='finflow'?{completed:1}:{status:'completed'}),completed_at:stamp};
 const tables={[config.progress]:[progress]};
 if(family==='finflow')tables.finflow_tool_log=[{id:29,user_id:'0007',tool_name:'read_file',params:' { "path": "../fixture" } ',result_summary:'full synthetic result',security_flag:null,mode:'vulnerable',timestamp:stamp}];
 return{family,tables,archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',review:{archiveDigest:'a'.repeat(64),tables:[]}};
}
async function archive(family){
 const raw=input(family),directory=await fs.mkdtemp(path.join(os.tmpdir(),'agent-workshop-archive-')),tables=[];
 const write=async(name,value)=>{await fs.writeFile(path.join(directory,name),value);return{bytes:Buffer.byteLength(value),sha256:crypto.createHash('sha256').update(value).digest('hex')};};
 for(const [name,rows] of Object.entries(raw.tables)){
  const columns=Object.keys(rows[0]);const content=rows.map(row=>JSON.stringify(columns.map(key=>row[key]===null?{type:'null'}:typeof row[key]==='number'?{type:'integer',value:String(row[key])}:{type:'text',value:row[key]}))+'\n').join('');
  tables.push({name,columns,rows:rows.length,file:name+'.jsonl',...await write(name+'.jsonl',content)});
 }
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(row=>({type:'table',name:row.name}))));
 await write('manifest.json',JSON.stringify({version:1,format:'owasp-ai-goat-sqlite-archive-v1',complete:true,files:[{name:FAMILIES[family].source,sourceSha256:'b'.repeat(64),schemaFile,schema,tables}]}));
 return directory;
}
module.exports={input,archive};

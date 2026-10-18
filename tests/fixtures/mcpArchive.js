'use strict';
function input(){return {archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',review:{archiveDigest:'a'.repeat(64),retainedTables:[]},tables:{
 mcp_workshop_progress:[{user_key:'0007',objective_id:'mcp_recon',completed:0,completed_at:null,created_at:'2025-01-02 03:04:05.123456'}],
 mcp_workshop_tool_log:[{id:{type:'integer',value:'29'},user_key:'0007',tool_name:'list_tools',args:' { "exact": true } ',result_summary:'synthetic private result',outcome:null,success:null,created_at:null}]
}};}
module.exports={input};
async function archive(){
 const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'mcp-archive-')),tables=[];
 const write=async(file,content)=>{await fs.writeFile(path.join(directory,file),content);return {bytes:Buffer.byteLength(content),sha256:crypto.createHash('sha256').update(content).digest('hex')};};
 for(const [name,rows] of Object.entries(input().tables)){
  const columns=Object.keys(rows[0]),file=name+'.jsonl';
  const content=rows.map(row=>JSON.stringify(columns.map(key=>row[key]===null?{type:'null'}:typeof row[key]==='number'?{type:'integer',value:String(row[key])}:typeof row[key]==='object'?row[key]:{type:'text',value:row[key]}))+'\n').join('');
  tables.push({name,columns,rows:rows.length,file,...await write(file,content)});
 }
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(({name})=>({type:'table',name}))));
 await write('manifest.json',JSON.stringify({version:1,format:'dvaia-sqlite-archive-v1',complete:true,files:[{name:'mcp_workshop.db',sourceSha256:'b'.repeat(64),schemaFile,schema,tables}]}));
 return directory;
}
module.exports.archive=archive;

'use strict';
// Pure, checked-in reconstruction of the published SQL function bytes. Never
// executes SQL or substitutes expected hashes for reconstructed source.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const hash=text=>require('node:crypto').createHash('sha256').update(text).digest('hex');
const directory=path.join(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents');
function constants(sql){
 const values={};
 for(const m of sql.matchAll(/(\w+) (?:constant )?text := (E)?'((?:''|[^'])*)';/g)){
  let value=m[3].replaceAll("''","'");
  if(m[2])value=value.replace(/\\([nrt\\])/g,(_,c)=>({n:'\n',r:'\r',t:'\t','\\':'\\'})[c]);
  values[m[1]]=value;
 }
 for(const m of sql.matchAll(/(\w+) (?:constant )?text := \$(\w+)\$([\s\S]*?)\$\2\$;/g))values[m[1]]=m[3];
 return values;
}
function evaluate(expression,values){
 return expression.split('||').map(part=>{
  const token=part.trim();
  if(Object.hasOwn(values,token))return values[token];
  const parsed=constants(`value text := ${token};`);
  assert(Object.hasOwn(parsed,'value'),`Unsupported SQL source expression: ${token}`);
  return parsed.value;
 }).join('');
}
function apply(body,sql){
 const values=constants(sql);
 assert.equal(hash(body),values.old_guard_sha256||values.old_guard_hash);
 for(const m of sql.matchAll(/guard_source\s*:=\s*replace\(guard_source,\s*(E?'(?:[^']|'')*'|[a-zA-Z_]\w*),\s*([\s\S]*?)\);/g)){
  const from=evaluate(m[1],values),to=evaluate(m[2],values);
  assert.equal(body.split(from).length,2,'Unique replacement anchor required');body=body.replace(from,to);
 }
 if(values.upgraded_guard_sha256||values.repaired_guard_sha256)
  assert.equal(hash(body),values.upgraded_guard_sha256||values.repaired_guard_sha256);
 return body;
}
function reconstruct(){
 const read=name=>fs.readFileSync(path.join(directory,name),'utf8');
 let body=read('0082_merchant_mail_reads_registry_successor.sql').match(/AS \$\$([\s\S]*?)\$\$;/)[1];
 for(const prefix of ['0084','0085','0087','0088','0089','0092','0096','0098','0100','0103','0104','0106']){
  const sql=read(fs.readdirSync(directory).find(name=>name.startsWith(prefix+'_'))),v=constants(sql);
  if(prefix==='0096'){
   assert.equal(hash(body),v.old_guard_sha256||v.old_guard_hash);
   const anchor=` IF encode(NEW.successor_sha256,'hex')='${v.old_hash}' THEN`;
   assert.equal(body.split(anchor).length,2);body=body.replace(anchor,v.branch+anchor);
  }else body=apply(body,sql);
 }
 return body;
}
module.exports={hash,constants,evaluate,apply,reconstruct,directory};

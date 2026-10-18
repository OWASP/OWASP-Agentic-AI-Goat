'use strict';
const {Query}=require('pg');
const {fail}=require('./contract');
// Evented query collection avoids pg's default accumulation of every row before
// a result-size check. The caller owns connection termination/drain on failure.
function collectQuery(client,sql,{signal,maxRows=1000,maxBytes=1024*1024,maxColumns=128,QueryType=Query,onFields,values=[]}={}){
 if(!Array.isArray(values)||Object.getPrototypeOf(values)!==Array.prototype||values.length>2||Reflect.ownKeys(values).length!==values.length+1)throw fail('ANALYTICS_QUERY_PARAMETERS');
 const parameters=[];for(let i=0;i<values.length;i++){const d=Object.getOwnPropertyDescriptor(values,String(i));if(!d||!Object.hasOwn(d,'value')||typeof d.value!=='string'||!d.value.isWellFormed()||d.value.includes('\0')||Buffer.byteLength(d.value)>131072)throw fail('ANALYTICS_QUERY_PARAMETERS');parameters.push(d.value);}
 return new Promise((resolve,reject)=>{
  const query=new QueryType({text:sql,values:parameters,queryMode:'extended'});const rows=[];let bytes=2,settled=false;
  const abort=()=>finish(signal?.reason||fail('ANALYTICS_QUERY_ABORTED'));
  const closed=()=>finish(fail('ANALYTICS_QUERY_CONNECTION_CLOSED'));
  const finish=(error,result)=>{if(settled)return;settled=true;signal?.removeEventListener('abort',abort);client.off('end',closed);client.off('error',closed);error?reject(error):resolve(result);};
  // pg query_timeout installs a callback and suppresses error events.
  query.callback=error=>{if(error)finish(error);};
  query.on('error',error=>finish(error));
  query.on('row',row=>{
   if(settled)return;
   try{const text=JSON.stringify(row);bytes+=Buffer.byteLength(text)+1;
    if(rows.length>=maxRows||bytes>maxBytes||!row||Object.keys(row).length>maxColumns)throw fail('ANALYTICS_QUERY_BUDGET');
    rows.push(row);
   }catch(error){finish(error);}
  });
  query.on('end',result=>{
   if(settled)return;
   const columns=result.fields?.map(f=>f.name);
   if(!Array.isArray(columns)||columns.length>maxColumns||new Set(columns).size!==columns.length||columns.some(c=>typeof c!=='string'||!c||Buffer.byteLength(c)>256)||result.rowCount!==rows.length)return finish(fail('ANALYTICS_QUERY_SHAPE'));
   try{onFields?.(result.fields,rows);}catch(error){return finish(error);}
   finish(null,{sql,columns,rows,row_count:rows.length,error:null});
  });
  client.once('end',closed);client.once('error',closed);signal?.addEventListener('abort',abort,{once:true});
  if(signal?.aborted)return abort();
  try{client.query(query);}catch(error){finish(error);}
 });
}
module.exports={collectQuery};

'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {randomUUID,createHash}=require('node:crypto');
const express=require('express');const {z}=require('zod');
const {McpServer}=require('@modelcontextprotocol/sdk/server/mcp.js');
const {StreamableHTTPServerTransport}=require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const {isInitializeRequest}=require('@modelcontextprotocol/sdk/types.js');
const {StreamableHTTPClientTransport}=require('@modelcontextprotocol/sdk/client/streamableHttp.js');
async function createOwnedShadowPeer({text,name='owned-policy-peer',version='1.0.0'}={}){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'dvaia-shadow-sdk-'));await fs.chmod(directory,0o700);
 const file=path.join(directory,'policy.txt');await fs.writeFile(file,text,{mode:0o600,flag:'wx'});
 const app=express(),sessions=new Map(),servers=new Set(),requests=[],reads=[];app.use(express.json({limit:'16kb'}));
 app.post('/mcp',async(req,res)=>{
  requests.push({method:req.body?.method,path:req.path});let transport=sessions.get(req.headers['mcp-session-id']);
  if(!transport){
   if(!isInitializeRequest(req.body)||sessions.size>=4)return res.status(400).json({error:'Session unavailable'});
   const server=new McpServer({name,version});servers.add(server);
   server.registerTool('read_policy',{description:'Read the current namespace-owned policy document',inputSchema:{section:z.literal('policy')}},async()=>{
    const content=await fs.readFile(file,'utf8');reads.push(createHash('sha256').update(content).digest('hex'));return{content:[{type:'text',text:content}]};
   });
   transport=new StreamableHTTPServerTransport({sessionIdGenerator:randomUUID,enableJsonResponse:true,onsessioninitialized:id=>sessions.set(id,transport)});
   await server.connect(transport);
  }
  try{await transport.handleRequest(req,res,req.body);}catch{if(!res.headersSent)res.status(500).end();}
 });
 app.get('/mcp',(_req,res)=>res.status(405).end());
 app.delete('/mcp',async(req,res)=>{const t=sessions.get(req.headers['mcp-session-id']);if(t){sessions.delete(req.headers['mcp-session-id']);await t.close();}res.status(200).json({});});
 const listener=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 const endpoint=`http://127.0.0.1:${listener.address().port}/mcp`;
 return{endpoint,name,version,requests,reads,
  async replacePolicy(value){await fs.writeFile(file,value,{mode:0o600});},
  async close(){for(const s of servers)await s.close();await new Promise(resolve=>listener.close(resolve));await fs.rm(directory,{recursive:true,force:true});},
 };
}
function controlledConnector(peers){
 const endpoints=new Map(peers.map(p=>[p.endpoint,p]));
 return{async open({endpoint,scopeDigest}){
  const peer=endpoints.get(endpoint);if(!peer||(peer.boundScopeDigest&&peer.boundScopeDigest!==scopeDigest))throw Object.assign(new Error('Endpoint outside fixture'),{code:'SHADOW_ENDPOINT_DENIED'});
  peer.boundScopeDigest=scopeDigest;
  const transport=new StreamableHTTPClientTransport(new URL(endpoint),{fetch:async(url,options)=>{
   if(String(url)!==endpoint)throw Error('Unexpected SDK destination');
   const response=await fetch(url,{...options,redirect:'error'});
   if(response.status===405||!response.body)return response;
   const reader=response.body.getReader(),parts=[];let size=0;
   while(true){const item=await reader.read();if(item.done)break;size+=item.value.byteLength;if(size>65536){await reader.cancel();throw Error('Fixture response exceeds bound');}parts.push(item.value);}
   return new Response(Buffer.concat(parts),{status:response.status,headers:response.headers});
  }});
  return{transport,attestation:{endpoint,scopeDigest,authentication:'owned-control-manifest',manifestDigest:'f'.repeat(64),peerKey:peer.endpoint,approved:peer.approved===true,expectedServerName:peer.name,expectedServerVersion:peer.version},close:async()=>{await transport.close();}};
 }};
}
module.exports={createOwnedShadowPeer,controlledConnector};

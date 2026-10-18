'use strict';
// SDK traffic stays inside the attested network namespace. No learner endpoint
// is mapped to a canned response; it is passed directly to the SDK transport.
const fs=require('node:fs/promises'),syncFs=require('node:fs'),http=require('node:http'),crypto=require('node:crypto');
const {McpServer}=require('@modelcontextprotocol/sdk/server/mcp.js');
const {Client}=require('@modelcontextprotocol/sdk/client/index.js');
const {StreamableHTTPServerTransport}=require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const {StreamableHTTPClientTransport}=require('@modelcontextprotocol/sdk/client/streamableHttp.js');
const {isInitializeRequest}=require('@modelcontextprotocol/sdk/types.js');
const {z}=require('zod');
const {peers,validate}=require('./contract');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const error=code=>Object.assign(Error(code),{code});
async function run(input,{inherited=true}={}){
 const selected=validate(input),listeners=[],sessions=[],hits=[],reads=[];let client;
 const directory=await fs.mkdtemp('/tmp/shadow-policy-');await fs.chmod(directory,0o700);
 try{
  for(const definition of peers){
   const file=directory+'/'+definition.id+'.txt';await fs.writeFile(file,input.sources[definition.id],{flag:'wx',mode:0o600});
   const transports=new Map();
   const listener=http.createServer(async(req,res)=>{
    try{
     if(req.url!=='/mcp'){res.writeHead(404);res.end();return;}
     if(req.method==='GET'){res.writeHead(405);res.end();return;}
     if(req.method==='DELETE'){const t=transports.get(req.headers['mcp-session-id']);if(t){transports.delete(req.headers['mcp-session-id']);await t.close();}res.end('{}');return;}
     if(req.method!=='POST')throw error('METHOD_DENIED');
     const chunks=[];let size=0;for await(const c of req){size+=c.length;if(size>16384)throw error('REQUEST_LIMIT');chunks.push(c);}
     const body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(hits.length>=16)throw error('REQUEST_LIMIT');hits.push({peer:definition.id,method:body.method,path:req.url});
     let transport=transports.get(req.headers['mcp-session-id']);
     if(!transport){
      if(!isInitializeRequest(body)||transports.size>=2)throw error('SESSION_DENIED');
      const server=new McpServer({name:'policy-library',version:'1.0.0'});sessions.push(server);
      server.registerTool('read_policy',{description:'Read the namespace policy file',inputSchema:{section:z.literal('policy')}},async()=>{const text=await fs.readFile(file,'utf8');reads.push({peer:definition.id,sourceSha256:sha(text)});return{content:[{type:'text',text}]};});
      transport=new StreamableHTTPServerTransport({sessionIdGenerator:crypto.randomUUID,enableJsonResponse:true,onsessioninitialized:id=>transports.set(id,transport)});await server.connect(transport);
     }
     await transport.handleRequest(req,res,body);
    }catch{if(!res.headersSent)res.writeHead(400);res.end();}
   });listeners.push(listener);listener.requestTimeout=2000;listener.headersTimeout=2000;
   await new Promise((resolve,reject)=>{listener.once('error',reject);listener.listen(inherited?{fd:definition.fd}:{host:new URL(definition.endpoint).hostname,port:Number(new URL(definition.endpoint).port||80)},resolve);});
  }
  if(inherited){syncFs.closeSync(3);syncFs.closeSync(5);}
  client=new Client({name:'dvaia-owned-shadow',version:'1.0.0'});
  const transport=new StreamableHTTPClientTransport(new URL(input.endpoint),{fetch:async(url,options)=>{
   if(String(url)!==input.endpoint)throw error('SHADOW_DESTINATION_CHANGED');
   const response=await fetch(url,{...options,redirect:'error',signal:AbortSignal.timeout(3000)});
   if(!response.body||response.status===405)return response;
   const reader=response.body.getReader(),parts=[];let bytes=0;
   while(true){const part=await reader.read();if(part.done)break;bytes+=part.value.byteLength;if(bytes>32768){await reader.cancel();throw error('SHADOW_RESPONSE_LIMIT');}parts.push(part.value);}
   return new Response(Buffer.concat(parts),{status:response.status,headers:response.headers});
  }});
  await client.connect(transport,{timeout:3000});const identity=client.getServerVersion();const catalog=await client.listTools(undefined,{timeout:3000});
  if(catalog.nextCursor||catalog.tools?.length!==1||catalog.tools[0].name!=='read_policy')throw error('SHADOW_CATALOG_CHANGED');
  const catalogDigest=require('../owned-http/canonical').canonicalDigest(catalog.tools);let result=null;
  if(input.action==='invoke'){if(catalogDigest!==input.expectedCatalogDigest)throw error('SHADOW_CATALOG_CHANGED');result=await client.callTool({name:input.remoteName,arguments:input.args},undefined,{timeout:3000});}
  return {version:1,endpoint:input.endpoint,peerId:selected.id,approved:selected.id==='approved',identity,catalog:catalog.tools,catalogDigest,result,hits,reads,isolationAttested:process.env.DVAIA_OWNED_HTTP_ATTESTED==='1'};
 }finally{await client?.close().catch(()=>{});for(const s of sessions)await s.close().catch(()=>{});for(const l of listeners){l.closeAllConnections();await new Promise(resolve=>l.listening?l.close(resolve):resolve());}await fs.rm(directory,{recursive:true,force:true});}
}
async function main(){if(process.platform!=='linux'||process.env.DVAIA_OWNED_HTTP_ATTESTED!=='1'||syncFs.existsSync('/proc/self/status'))throw error('SHADOW_UNATTESTED');let size=0;const parts=[];for await(const c of process.stdin){size+=c.length;if(size>49152)throw error('SHADOW_INPUT_LIMIT');parts.push(c);}process.stdout.write(JSON.stringify(await run(JSON.parse(Buffer.concat(parts))))+'\n');}
if(require.main===module)main().catch(()=>{process.stderr.write('owned-shadow:operation_failed\n');process.exitCode=70;});
module.exports={run,validate,peers};

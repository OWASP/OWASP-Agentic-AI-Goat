'use strict';
const fs=require('node:fs'),path=require('node:path'),http=require('node:http');const {createPolicy}=require('./applicationCapacityProvider');
const root=fs.realpathSync(process.env.DVAIA_CAPACITY_ROOT);if(root!==process.env.DVAIA_CAPACITY_ROOT)throw Error('Owned capacity root required');
const policy=createPolicy(),held=new Set();let hold=false,holdTimer,active=0,peak=0,requests=0,closed=false,holdId=0,expired=false;
function release(){hold=false;clearTimeout(holdTimer);for(const go of held)go();held.clear();}
const server=http.createServer(async(req,res)=>{try{
 if(req.method==='GET'&&req.url==='/__status'){res.setHeader('content-type','application/json');return res.end(JSON.stringify({pid:process.pid,active,peak,held:held.size,holding:hold,holdId,expired,...policy.snapshot()}));}
 if(req.method==='POST'&&req.url==='/__hold'){release();hold=true;holdId++;expired=false;holdTimer=setTimeout(()=>{expired=true;release();},10000);return res.end('{}');}
 if(req.method==='POST'&&req.url==='/__release'){release();return res.end('{}');}
 if(req.method==='GET'&&req.url==='/api/tags')return res.end(JSON.stringify({models:[{name:'capacity-controlled-v1'}]}));
 if(req.method!=='POST'||!['/api/chat','/api/generate'].includes(req.url))throw Error('Undeclared provider endpoint');
 if(++requests>6000)throw Error('Provider aggregate budget');let bytes=0,chunks=[];for await(const part of req){bytes+=part.length;if(bytes>524288)throw Error('Provider input bound');chunks.push(part);}
 const body=JSON.parse(Buffer.concat(chunks));if(req.url==='/api/generate'&&(typeof body.prompt!=='string'||body.messages!==undefined))throw Error('Invalid generation request');active++;peak=Math.max(peak,active);
 try{if(hold)await new Promise(resolve=>held.add(resolve));if(closed)return;await new Promise(r=>setTimeout(r,25));if(res.destroyed)return;const generate=req.url==='/api/generate';const output=policy.respond(generate?{model:body.model,messages:[{role:'user',content:body.prompt}]}:body);const wire=generate?{model:output.model,done:true,response:output.message.content}:output;res.setHeader('content-type',body.stream===false?'application/json':'application/x-ndjson');if(body.stream===false)res.end(JSON.stringify(wire));else res.end(JSON.stringify({...wire,done:false})+'\n'+JSON.stringify(generate?{model:wire.model,done:true,response:''}:{model:wire.model,done:true,message:{role:'assistant',content:''}})+'\n');}finally{active--;}
 }catch{res.statusCode=503;res.end(JSON.stringify({error:'Controlled capacity transport unavailable'}));}});
server.listen(0,'127.0.0.1',()=>fs.writeFileSync(path.join(root,'capacity-provider.json'),JSON.stringify({pid:process.pid,port:server.address().port,actualModel:false}),{mode:0o600}));
process.on('SIGTERM',()=>{closed=true;release();server.close();server.closeAllConnections();});

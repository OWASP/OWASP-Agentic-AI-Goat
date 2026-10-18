'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http'),path=require('node:path');
const express=require('express');
const {createTrackRequestCompletion}=require('../server/middleware/trackRequestCompletion');
const gatePath=require.resolve('../server/middleware/eventGate');
const gate=require(gatePath);
function request(port,pathName){return new Promise((resolve,reject)=>{const req=http.get({host:'127.0.0.1',port,path:pathName},response=>{const chunks=[];response.on('data',chunk=>chunks.push(chunk));response.once('end',()=>resolve({status:response.statusCode,body:Buffer.concat(chunks).toString()}));response.once('error',reject);});req.once('error',reject);});}
test('exact cached event gate closes new API work, permits health, drains admitted work and restores',async t=>{
  assert.equal(require.cache[gatePath].filename,fsReal(gatePath));assert.equal(require.cache[gatePath].exports.eventGate,gate.eventGate);
  const original={enabled:process.env.EVENT_GATE_ENABLED,password:process.env.EVENT_GATE_PASSWORD};
  t.after(()=>{for(const [key,value] of Object.entries(original)){if(value===undefined)delete process.env[`EVENT_GATE_${key.toUpperCase()}`];else process.env[`EVENT_GATE_${key.toUpperCase()}`]=value;}});
  process.env.EVENT_GATE_ENABLED='false';delete process.env.EVENT_GATE_PASSWORD;
  const monitor={systemStats:{activeConnections:0},recordMetrics(){}};let release;const held=new Promise(resolve=>{release=resolve;});
  const app=express();app.use(createTrackRequestCompletion(monitor));app.use(gate.eventGate);app.get('/api/held',async(req,res)=>{await held;res.json({ok:true});});app.get('/api/probe',(req,res)=>res.json({ok:true}));app.get('/api/monitoring/health',(req,res)=>res.json({status:'healthy',system:{activeConnections:monitor.systemStats.activeConnections}}));
  const server=http.createServer(app);await new Promise((resolve,reject)=>server.listen(0,'127.0.0.1',resolve).once('error',reject));t.after(()=>new Promise(resolve=>server.close(resolve)));const port=server.address().port;
  const admitted=request(port,'/api/held');while(monitor.systemStats.activeConnections!==1)await new Promise(resolve=>setTimeout(resolve,5));
  const maintenancePassword=require('node:crypto').randomBytes(32).toString('base64url');process.env.EVENT_GATE_PASSWORD=maintenancePassword;process.env.EVENT_GATE_ENABLED='true';assert.deepEqual(gate.assertEventGateConfiguration(process.env),{enabled:true,password:maintenancePassword});
  assert.equal((await request(port,'/api/probe')).status,401);const health=await request(port,'/api/monitoring/health');assert.equal(health.status,200);assert.equal(JSON.parse(health.body).status,'healthy');assert.equal(monitor.systemStats.activeConnections,1,'held admitted request remains the only active work after probes settle');
  release();assert.equal((await admitted).status,200);while(monitor.systemStats.activeConnections!==0)await new Promise(resolve=>setTimeout(resolve,5));
  if(original.enabled===undefined)delete process.env.EVENT_GATE_ENABLED;else process.env.EVENT_GATE_ENABLED=original.enabled;if(original.password===undefined)delete process.env.EVENT_GATE_PASSWORD;else process.env.EVENT_GATE_PASSWORD=original.password;
  assert.equal((await request(port,'/api/probe')).status,200);
});
function fsReal(value){return require('node:fs').realpathSync(value);}

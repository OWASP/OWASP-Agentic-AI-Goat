'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const tls = require('node:tls');
const http = require('node:http');
const dns = require('node:dns');
const dgram = require('node:dgram');
const workers = require('node:worker_threads');
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { once } = require('node:events');
const { installDeletionNetworkGuard } = require('./adminStudentDeletionNetworkGuard');
const chromium = fs.realpathSync(process.execPath);
const blocked = { code: 'DELETION_EGRESS_BLOCKED' };

test('owned exact TCP endpoint works; alternate forms are rejected before connection', async () => {
  const server = net.createServer(socket => socket.end());
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port;
  const guard = installDeletionNetworkGuard({ postgresPort: port, chromium });
  try {
    const socket = net.connect(port, '127.0.0.1'); await once(socket, 'close');
    for (const options of [{port,host:'localhost'}, {port,host:'::1'},
      {port:port === 65535 ? port-1 : port+1,host:'127.0.0.1'}, {path:'/tmp/not-owned'},
      {port:{valueOf(){throw Error('must not coerce');}},host:'127.0.0.1'},
      {port,host:'127.0.0.1',lookup:()=>{throw Error('must not run');}}]) {
      const candidate = new net.Socket();
      try { assert.throws(() => candidate.connect(options), blocked); } finally { candidate.destroy(); }
    }
    assert.throws(() => tls.connect({port,host:'127.0.0.1'}), blocked);
    assert.throws(() => http.get(`http://127.0.0.1:${port}/`), blocked);
    assert.throws(() => dns.lookup('example.invalid',()=>{}), blocked);
    await assert.rejects(fetch('http://127.0.0.1:11434/'), blocked);
    assert.throws(() => cp.execFileSync(chromium,['--version']), blocked);
    const udp = dgram.createSocket('udp4');
    try { assert.throws(()=>udp.send('x',port,'127.0.0.1'),blocked); } finally { udp.close(); }
    assert.throws(()=>new workers.Worker('process.exit()', {eval:true}),blocked);
    const { Client } = require('undici');
    const client = new Client('http://127.0.0.1:11434');
    try { await assert.rejects(client.request({path:'/',method:'GET'}),blocked); }
    finally { await client.close(); }
    assert.equal(guard.snapshot().postgresAttempts,1);
    assert.equal(guard.snapshot().blockedAttempts,14);
    assert.equal(guard.snapshot().intact,true);
  } finally { guard.restore(); await new Promise(resolve=>server.close(resolve)); }
});

test('only one canonical executable with private profile and pipe CDP may spawn', () => {
  const parent = path.resolve(__dirname,'../../tasks/qualification');
  const owned = fs.mkdtempSync(path.join(parent,'run-network-guard-')); fs.chmodSync(owned,0o700);
  const original = cp.ChildProcess.prototype.spawn;
  let actual = 0;
  cp.ChildProcess.prototype.spawn = () => { actual++; return 0; };
  const guard = installDeletionNetworkGuard({postgresPort:54321,chromium});
  const options = { file:chromium,args:[chromium,`--user-data-dir=${owned}`,'--remote-debugging-pipe'],
    stdio:['pipe','pipe','pipe','pipe','pipe'],envPairs:[] };
  try {
    assert.throws(()=>cp.ChildProcess.prototype.spawn.call({}, {...options,file:'/bin/sh'}),blocked);
    assert.throws(()=>cp.ChildProcess.prototype.spawn.call({}, {...options,args:[...options.args,'--remote-debugging-port=1']}),blocked);
    assert.throws(()=>cp.ChildProcess.prototype.spawn.call({}, {...options,stdio:[{},{},{},{type:'fd'},{type:'pipe'}]}),blocked);
    // Exercise Node's genuine public spawn normalization without launching a
    // process: the saved prototype implementation above is the controlled sink.
    const child = cp.spawn(chromium, options.args.slice(1), {stdio:options.stdio,env:{}});
    assert.ok(child instanceof cp.ChildProcess);
    assert.throws(()=>cp.ChildProcess.prototype.spawn.call({},options),blocked);
    assert.equal(actual,1); assert.equal(guard.snapshot().chromeSpawnsAllowed,1);
  } finally { guard.restore(); cp.ChildProcess.prototype.spawn=original; fs.rmdirSync(owned); }
});

test('patch integrity and restoration are explicit and fail closed', () => {
  const original = net.Socket.prototype.connect;
  const guard = installDeletionNetworkGuard({postgresPort:54321,chromium});
  assert.throws(()=>installDeletionNetworkGuard({postgresPort:54321,chromium}),/already installed/);
  net.Socket.prototype.connect = original;
  assert.equal(guard.snapshot().intact,false);
  assert.throws(()=>guard.restore(),/modified/);
  assert.equal(net.Socket.prototype.connect,original);
  assert.equal(guard.snapshot().active,false);
});

test('real owned Server.listen resolves only literal loopback without DNS', async () => {
  const original = dns.lookup;
  let externalLookups = 0;
  dns.lookup = () => { externalLookups++; throw Error('must not invoke DNS'); };
  const guard = installDeletionNetworkGuard({postgresPort:54321,chromium});
  const server = http.createServer();
  try {
    server.listen(0,'127.0.0.1'); await once(server,'listening');
    assert.equal(server.address().address,'127.0.0.1');
    assert.equal(externalLookups,0);
    assert.ok(guard.snapshot().literalLoopbackLookups >= 1);
    assert.equal(guard.snapshot().nonPostgresAttempts,0);
    assert.equal(guard.snapshot().dnsAttempts,0);
    for (const name of ['localhost','example.invalid','192.0.2.1','::1']) {
      assert.throws(()=>dns.lookup(name,{all:true},()=>{}),blocked);
    }
    assert.throws(()=>dns.lookup('127.0.0.1',{family:6},()=>{}),blocked);
    assert.equal(externalLookups,0);
    assert.equal(guard.snapshot().blockedAttempts,5);
  } finally {
    if (server.listening) await new Promise(resolve=>server.close(resolve));
    guard.restore(); dns.lookup=original;
  }
});

test('exact production bcrypt worker is bounded, joined and counted separately', {timeout:5000}, async () => {
  const bcrypt = require('bcryptjs');
  const hash = await bcrypt.hash('synthetic-test-password',4);
  const guard = installDeletionNetworkGuard({postgresPort:54321,chromium});
  const filename = path.resolve(__dirname,'../../server/agent-runtime/workers/passwordComparisonWorker.js');
  const options = {env:{},execArgv:[],resourceLimits:{maxOldGenerationSizeMb:64}};
  const owned = [];
  try {
    for (const invalid of [{...options,eval:true},{...options,env:{SECRET:'no'}},
      {...options,execArgv:['--inspect']},{...options,resourceLimits:{maxOldGenerationSizeMb:128}}])
      assert.throws(()=>new workers.Worker(filename,invalid),blocked);
    assert.throws(()=>new workers.Worker(__filename,options),blocked);
    for (let i=0;i<4;i++) owned.push(new workers.Worker(filename,options));
    assert.throws(()=>new workers.Worker(filename,options),blocked);
    assert.throws(()=>guard.restore(),/must exit/);
    const reply = once(owned[0],'message');
    owned[0].postMessage({id:1,password:'synthetic-test-password',hash});
    assert.deepEqual((await reply)[0],{id:1,ok:true,match:true});
    assert.equal(guard.snapshot().passwordWorkersLive,4);
  } finally { await Promise.all(owned.map(worker=>worker.terminate())); guard.restore(); }
  assert.equal(guard.snapshot().passwordWorkersStarted,4);
  assert.equal(guard.snapshot().passwordWorkersExited,4);
  assert.equal(guard.snapshot().passwordWorkersLive,0);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createSecureShopSystemDiagnosticComposition: create} = require('../server/services/secureshopSystemDiagnosticComposition');
const dependencies = () => ({modeAuthority:{capture(){},assertToken(){}},agentsPool:{query(){}},personaAuthority:{capture(){}},audit:{append(){}},
  client:{execute(){throw Error('must not execute');},async assertReady(){return true;}},authenticatePersona(){}});

test('diagnostic composition exposes routes only after database and remote readiness', async () => {
  const input = dependencies(), calls = []; let release;
  const gate = new Promise(resolve => {release=resolve;});
  const repository = {async checkReadiness(){calls.push('database');await gate;return {ready:true};}};
  input.client.assertReady=async()=>{calls.push('remote');return true;};
  const service={execute(){},operation(){},administration(){}};
  const pending=create(input,{createRepository: args=>{assert.equal(args.personaAuthority,input.personaAuthority);return repository;},
    createService: args=>{calls.push('service');assert.equal(args.repository,repository);assert.equal(args.modeAuthority,input.modeAuthority);return service;},
    createRouter: args=>{calls.push('router');assert.equal(args.service,service);return ()=>{};}});
  await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(calls,['database']);
  release();const result=await pending;
  assert.deepEqual(calls,['database','remote','service','router']);assert.equal(result.ready,true);assert.ok(Object.isFrozen(result));
});

test('diagnostic composition denies drift and missing authority before remote probes', async () => {
  for(const ready of [false,undefined,{}]) {
    const input=dependencies();let probes=0;
    input.client.assertReady=async()=>{probes++;return true;};
    await assert.rejects(create(input,{createRepository:()=>({checkReadiness:async()=>ready})}),/database unavailable/);
    assert.equal(probes,0);
  }
  await assert.rejects(create({...dependencies(),modeAuthority:undefined}),/dependencies required/);
  await assert.rejects(create({...dependencies(),personaAuthority:{}}),/dependencies required/);
  const input=dependencies();input.client.assertReady=async()=>false;
  await assert.rejects(create(input,{createRepository:()=>({checkReadiness:async()=>({ready:true})})}),/executor unavailable/);
});

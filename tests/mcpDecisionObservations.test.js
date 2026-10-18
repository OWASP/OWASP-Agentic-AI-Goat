'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {
 decideMcp,
 projectObservations,
 MAX_OBSERVATION_OUTPUT_BYTES,
 MAX_AGGREGATE_OBSERVATION_OUTPUT_BYTES,
}=require('../server/agent-runtime/mcpDecision');

test('oversized complete decision context stops before inference without rewriting arguments',async()=>{
 let calls=0;const events=[];
 const result=await decideMcp({message:'read',catalog:[],
  observations:[{toolUsed:'read_file',params:{path:'x'.repeat(70000)},toolResult:{output:'small'}}],
  execution:{check:async()=>{},trace:async event=>events.push(event)},
  model:{chatWithTools:async()=>{calls++;}},
 });
 assert.equal(calls,0);assert.equal(result.tool,null);
 assert.equal(events.at(-1).data.errorCode,'MCP_CONTEXT_LIMIT');
});

test('observation projection reports original UTF-8 size and preserves both ends with an explicit marker',()=>{
 const prefix='start-💥-';
 const suffix='-終わり-tail';
 const raw=prefix+'x'.repeat(MAX_OBSERVATION_OUTPUT_BYTES*2)+suffix;
 const [projected]=projectObservations([{toolUsed:'read_file',params:{path:'notes.txt'},toolResult:{output:raw}}]);

 assert.equal(projected.originalOutputBytes,Buffer.byteLength(raw));
 assert.equal(projected.outputTruncated,true);
 assert.ok(projected.output.startsWith(prefix));
 assert.ok(projected.output.endsWith(suffix));
 assert.match(projected.output,/\[TRUNCATED originalBytes=\d+ omittedBytes=\d+\]/);
 assert.ok(Buffer.byteLength(projected.output)<=MAX_OBSERVATION_OUTPUT_BYTES);
 assert.doesNotMatch(projected.output,/\uFFFD/);
 const omitted=Number(projected.output.match(/omittedBytes=(\d+)/)[1]);
 const retained=projected.output.replace(/\n\[TRUNCATED originalBytes=\d+ omittedBytes=\d+\]\n/,'');
 assert.equal(omitted,Buffer.byteLength(raw)-Buffer.byteLength(retained));
});

test('observation projection bounds aggregate output while retaining every call linkage',()=>{
 const observations=Array.from({length:4},(_,index)=>({
  toolUsed:'read_file',
  params:{path:`file-${index}.txt`},
  toolResult:{output:`head-${index}-`+'z'.repeat(12000)+`-tail-${index}`},
 }));
 const projected=projectObservations(observations);

 assert.deepEqual(projected.map(item=>item.tool),observations.map(item=>item.toolUsed));
 assert.deepEqual(projected.map(item=>item.args),observations.map(item=>item.params));
 assert.ok(projected.every((item,index)=>item.output.startsWith(`head-${index}-`)&&item.output.endsWith(`-tail-${index}`)));
 assert.ok(projected.reduce((total,item)=>total+Buffer.byteLength(item.output),0)<=MAX_AGGREGATE_OBSERVATION_OUTPUT_BYTES);
});

test('decideMcp sends structured projected observations without changing raw tool arguments',async()=>{
 let messages;
 const params={command:'printf "💥"; cat ../secret'};
 const model={chatWithTools:async(input)=>{messages=input;return{content:JSON.stringify({tool:'none',params:{}})};}};
 await decideMcp({
  model,
  message:'continue',
  catalog:[],
  observations:[{toolUsed:'run_command',params,toolResult:{output:'first-'+('q'.repeat(20000))+'-last'}}],
 });

 const call=messages.at(-2).tool_calls[0];
 assert.equal(messages.at(-2).role,'assistant');
 assert.equal(messages.at(-1).role,'tool');
 assert.equal(messages.at(-1).tool_call_id,call.id);
 const observed=[JSON.parse(messages.at(-1).content)];
 assert.deepEqual(JSON.parse(call.function.arguments),params);
 const converted=require('../server/agent-runtime/providers/langchainProvider').messagesForLangChain(messages);
 assert.equal(converted.at(-2)._getType(),'ai');
 assert.equal(converted.at(-1)._getType(),'tool');
 assert.equal(converted.at(-1).tool_call_id,call.id);
 assert.equal(observed[0].originalOutputBytes,Buffer.byteLength('first-'+('q'.repeat(20000))+'-last'));
 assert.equal(observed[0].outputTruncated,true);
 assert.match(observed[0].output,/\[TRUNCATED /);
 assert.ok(observed[0].output.endsWith('-last'));
});

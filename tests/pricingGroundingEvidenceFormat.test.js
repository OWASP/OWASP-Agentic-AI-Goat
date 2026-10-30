'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const F = require('../server/agent-runtime/pricingGroundingEvidenceFormat');
const sha = value => createHash('sha256').update(value).digest('hex');
const observation = {grounded:false, proposal:{price:14.37}, extra:['😀', 'a\r\nb', false, null]};
const answer = 'A 😀 e\u0301\r\n "quoted" \\ source\n尾';
function user(stage='effect') {
  return JSON.stringify({tool_observation:observation,answer,
    ...(stage==='effect'?{answer_passages:[{id:'p0',content:answer}]}:
      {selected_claim_quote:answer,server_bound_source_sha256:sha(JSON.stringify(observation))})});
}

test('effect and support blocks preserve every canonical byte through UTF-8 transport',()=>{
  for (const stage of ['effect','support']) {
    const raw=user(stage), encoded=F.encode(raw,stage);
    assert.equal(F.decode(Buffer.from(encoded).toString('utf8'),stage),raw);
    assert.notEqual(encoded,raw);
    assert.match(encoded,/<<<OWASP_AI_GOAT_PRICING_EVIDENCE_V1:BEGIN>>>/);
    assert.equal(encoded.includes('expectedVerdict'),false);
  }
});

test('the promoted representation matches the reviewed length-framed grammar exactly',()=>{
  const raw=user(), value=JSON.parse(raw), P=F.PREFIX;
  const expected=`${P}:BEGIN>>>\neffect\n`
    + Object.entries(value).map(([key,item])=>{
      const body=key==='answer'?item:JSON.stringify(item);
      return `${P}:${key}:${body.length}>>>\n${body}\n`;
    }).join('')+`${P}:END>>>`;
  assert.equal(F.encode(raw),expected);
});

test('collisions in every evidence component, malformed Unicode and overflow fail closed',()=>{
  for (const change of [v=>{v.answer+=F.PREFIX;},v=>{v.tool_observation.extra=F.PREFIX;},
    v=>{v.answer_passages[0].content+=F.PREFIX;}]) {
    const v=JSON.parse(user()); change(v);
    assert.throws(()=>F.encode(JSON.stringify(v)),/collision/);
  }
  const bad=JSON.parse(user());bad.answer='\ud800';
  assert.throws(()=>F.encode(JSON.stringify(bad)),/UTF-16/);
  bad.answer='x'.repeat(F.MAX_BYTES);
  assert.throws(()=>F.encode(JSON.stringify(bad)),/cap/);
  assert.throws(()=>F.decode('x'.repeat(F.MAX_BYTES+1)),/cap/);
});

test('decoder rejects changed order/length, extra/truncated blocks and noncanonical JSON',()=>{
  const raw=user(), wire=F.encode(raw);
  for(const changed of [wire+'\n',wire+wire,wire.slice(0,-1),wire.replace(':answer:',':unknown:'),
    wire.replace(/:tool_observation:\d+/,':tool_observation:0'),
    wire.replace(/:tool_observation:\d+/,':tool_observation:01')])assert.throws(()=>F.decode(changed));
  assert.throws(()=>F.encode(' '+raw));
  assert.throws(()=>F.encode(JSON.stringify({...JSON.parse(raw),extra:true})));
  assert.throws(()=>F.encode(raw,'other'));
  assert.throws(()=>F.decode(wire,'support'));
});

test('support preserves the original exact-quote/source-hash binding',()=>{
  for(const change of [v=>{v.selected_claim_quote='invented';},v=>{v.server_bound_source_sha256='0'.repeat(64);},
    v=>{v.tool_observation.grounded=true;}]) {
    const v=JSON.parse(user('support'));change(v);
    assert.throws(()=>F.encode(JSON.stringify(v),'support'));
  }
});

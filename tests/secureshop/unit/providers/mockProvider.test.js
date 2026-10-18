const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../../..');
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));

test('MockProvider replays scripted tool_use then end_turn', async () => {
  const p = new MockProvider();
  p.script([
    { stop: 'tool_use', tool_uses: [{ name: 'product-search.search', args: { q: 'x' } }] },
    { stop: 'end_turn', text: 'Done.' },
  ]);

  const r1 = await p.chat({ messages: [], tools: [] });
  assert.equal(r1.stop_reason, 'tool_use');
  assert.equal(r1.tool_uses[0].name, 'product-search.search');

  const r2 = await p.chat({ messages: [], tools: [] });
  assert.equal(r2.stop_reason, 'end_turn');
  assert.equal(r2.text, 'Done.');
});

test('MockProvider reactive text uses last tool_result', async () => {
  const p = new MockProvider();
  p.script([
    {
      stop: 'end_turn_reactive',
      reactTo: 'tool_result',
      textMatcher: (r) => `saw:${r}`,
    },
  ]);
  const r = await p.chat({ messages: [{ role: 'tool', content: 'HELLO' }], tools: [] });
  assert.equal(r.text, 'saw:HELLO');
});

test('MockProvider counts unexpected calls', async () => {
  const p = new MockProvider();
  p.script([{ stop: 'end_turn', text: 'one' }]);
  await p.chat({ messages: [], tools: [] });
  await p.chat({ messages: [], tools: [] });  // no script left
  assert.equal(p.getUnexpectedCallCount(), 1);
});

test('MockProvider exposes an explicit scripted final capability and rejects scripted actions',async()=>{
  const p=new MockProvider();p.script([{stop:'end_turn',text:'fixture final'}]);
  assert.deepEqual(await p.finalResponse({}),{stop_reason:'end_turn',text:'fixture final',
    responseMode:'structured_final',mocked:true,usage:{inputTokens:null,outputTokens:null,totalTokens:null,attempts:1}});
  p.script([{stop:'tool_use',tool_uses:[{name:'system.read'}]}]);
  await assert.rejects(p.finalResponse({}),{code:'SECURESHOP_INVALID_DECISION'});
});

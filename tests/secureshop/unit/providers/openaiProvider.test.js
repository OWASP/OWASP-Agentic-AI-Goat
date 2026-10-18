const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../../..');
const { OpenAIProvider } = require(path.join(REPO, 'server/services/secureshop/providers/openaiProvider.js'));

function fakeOpenAI(port, response) {
  const srv = http.createServer((req, res) => {
    let body = ''; req.on('data', c => body += c);
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(response));
    });
  });
  return new Promise((r) => srv.listen(port, () => r(srv)));
}

test('OpenAIProvider maps tool_calls to unified shape', async () => {
  const srv = await fakeOpenAI(15200, {
    choices: [{
      message: {
        role: 'assistant',
        content: null,
        tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'product-search__search', arguments: JSON.stringify({ q: 'x' }) } }],
      },
      finish_reason: 'tool_calls',
    }],
  });
  const p = new OpenAIProvider({ apiKey: 'sk-test', baseUrl: 'http://127.0.0.1:15200' });
  const r = await p.chat({ system: 's', messages: [], tools: [{ agent: 'product-search', tool: 'search', description: '', inputSchema: {} }], role: 'customer' });
  assert.equal(r.stop_reason, 'tool_use');
  assert.equal(r.tool_uses[0].name, 'product-search.search');
  srv.close();
});

test('OpenAIProvider maps assistant text to end_turn', async () => {
  const srv = await fakeOpenAI(15201, {
    choices: [{
      message: { role: 'assistant', content: 'hi there' },
      finish_reason: 'stop',
    }],
  });
  const p = new OpenAIProvider({ apiKey: 'sk-test', baseUrl: 'http://127.0.0.1:15201' });
  const r = await p.chat({ system: '', messages: [], tools: [], role: 'customer' });
  assert.equal(r.stop_reason, 'end_turn');
  assert.equal(r.text, 'hi there');
  srv.close();
});

test('LangChain-backed providers expose only validated structured final responses',async()=>{
  const p=new OpenAIProvider({apiKey:'sk-test',model:'gpt-4o'}, {modelFactory:()=>({
    withStructuredOutput(schema,options){
      assert.deepEqual(schema.required,['answer']);assert.equal(options.method,'jsonSchema');
      return{async invoke(){return{parsed:{answer:'provider final'},raw:{usage_metadata:{input_tokens:2,output_tokens:3,total_tokens:5}}};}};
    },
  })});
  assert.deepEqual(await p.finalResponse({messages:[{role:'user',content:'answer'}]}),{
    provider:'openai',model:'gpt-4o',mocked:false,stop_reason:'end_turn',text:'provider final',
    responseMode:'structured_final',usage:{inputTokens:2,outputTokens:3,totalTokens:5,attempts:1}});
});

test('LangChain-backed final response preserves owner cancellation',async()=>{
  const controller=new AbortController();let entered;
  const started=new Promise(resolve=>{entered=resolve;});
  const p=new OpenAIProvider({apiKey:'sk-test',model:'gpt-4o'},{modelFactory:()=>({
    withStructuredOutput(){return{invoke:(_messages,{signal})=>new Promise((_resolve,reject)=>{
      signal.addEventListener('abort',()=>reject(signal.reason),{once:true});entered();
    })};},
  })});
  const pending=p.finalResponse({messages:[],signal:controller.signal});
  await started;controller.abort(new Error('OWNER_RESET'));
  await assert.rejects(pending,/OWNER_RESET/);
});

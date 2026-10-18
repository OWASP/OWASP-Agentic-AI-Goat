'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { JSDOM } = require('../client/node_modules/jsdom');
const swc = require('../client/node_modules/@swc/core');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { validateSearchEchoDomCapture } = require('../server/services/secureshopSearchEchoBrowserQualification');
const { createXssBrowserQualification } = require('../server/services/xssBrowserQualification');
const sha = value => createHash('sha256').update(value).digest('hex');
const mode = effectiveMode => ({ version:1,featureId:'customer_chat',policyVersion:'owned-catalog-and-cart-read-v1',
  effectiveMode,scope:{kind:'launch_feature',id:'customer_chat'} });
function fixture() {
  const dom = new JSDOM('<div id="sink"></div>');
  const { document } = dom.window;
  const React = { createElement(type, props, ...children) { return {type,props:{...props,children}}; } };
  const compile = filename => swc.transformSync(fs.readFileSync(filename,'utf8'),{
    jsc:{parser:{syntax:'ecmascript',jsx:true},target:'es2022',transform:{react:{runtime:'classic'}}},
    module:{type:'commonjs'} }).code;
  const componentModule={exports:{}};
  vm.runInNewContext('(function(require,module,exports){'+compile(path.join(__dirname,'../client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx'))+'})',
    {TextEncoder})(name=>{assert.equal(name,'react');return React;},componentModule,componentModule.exports);
  // Controlled React commit uses the actual component's returned tree/ref. No
  // JS in supplied markup is executed; this is capture plumbing, not XSS proof.
  const render = (v,parent) => {
    if (v==null || typeof v==='boolean') return;
    if (typeof v==='string') {parent.appendChild(document.createTextNode(v));return;}
    if (typeof v.type==='function') return render(v.type(v.props),parent);
    const el=document.createElement(v.type);
    for(const [k,val] of Object.entries(v.props)) {
      if(['children','dangerouslySetInnerHTML','ref'].includes(k)) continue;
      if(k==='style') {Object.assign(el.style,val);continue;}
      if(val!==undefined)el.setAttribute(k==='className'?'class':k,val);
    }
    parent.appendChild(el);
    if(v.props.dangerouslySetInnerHTML)el.innerHTML=v.props.dangerouslySetInnerHTML.__html;
    else for(const c of v.props.children.flat())render(c,el);
    v.props.ref?.(el);
  };
  const context={document,TextEncoder,Object,Error,globalThis:null};context.globalThis=context;
  const entryModule={exports:{}};
  vm.runInNewContext('(function(require,module,exports){'+compile(path.join(__dirname,'../client/src/pages/secureshop/searchEchoClientRenderer.jsx'))+'})',context)(name=>{
    if(name==='react')return React;
    if(name==='react-dom')return {flushSync:fn=>fn()};
    if(name==='react-dom/client')return {createRoot:sink=>({render:v=>render(v,sink)})};
    if(name==='./components/AgentLane/SearchEcho.jsx')return componentModule.exports;
    throw Error(name);
  },entryModule,entryModule.exports);
  return {dom,document,mount:context.__DVAIA_SEARCH_ECHO_MOUNT__};
}
function capture(snapshot,source='source') {
  return {version:1,originalSourceSha256:sha(source),instrumentedSourceSha256:sha('instrumented'),
    mountedSourceSha256:sha('projected'),snapshotSha256:canonicalDigest(snapshot),snapshot:JSON.parse(JSON.stringify(snapshot))};
}
function valid(value,source='source',m='vuln') {return validateSearchEchoDomCapture(value,{originalSourceSha256:sha(source),mode:m});}

test('actual component ref captures complete nodes, attributes, text, comments and inert template content; selectors cannot substitute root',()=>{
  const f=fixture();
  const body='<div data-testid="hop-echo-html"><!--kept--><a href="javascript:alert(1)">x &amp; y</a><template><img onerror="alert(2)"></template></div>';
  const snapshot=f.mount({echoHtml:body,modeCapability:mode('vuln'),captureDom:true});
  const c=capture(snapshot);
  assert.equal(valid(c),true);
  assert.deepEqual(c.snapshot.nodes[0].path,[]);
  assert.equal(c.snapshot.nodes[0].attributes.find(a=>a.name==='class').value,'ss-agent-lane__echo');
  assert.equal(c.snapshot.nodes[1].attributes.some(a=>a.name==='class'),false);
  assert.ok(c.snapshot.nodes.some(n=>n.type===8 && n.text==='kept'));
  assert.ok(c.snapshot.nodes.some(n=>n.type===3 && n.text==='x & y'));
  assert.ok(c.snapshot.nodes.some(n=>n.type===11));
  assert.ok(c.snapshot.nodes.some(n=>n.attributes?.some(a=>a.name==='href' && a.value==='javascript:alert(1)')));
  assert.ok(c.snapshot.nodes.some(n=>n.attributes?.some(a=>a.name==='onerror')));
  assert.equal(c.snapshot.phase,'react-ref-commit');
  f.dom.window.close();
});

test('six opposed markup diagnostics use renderer-owned DOM rather than syntax guesses',()=>{
  const literal='<img src=x onerror="alert(\'owned\')">';
  const examples=[
    {html:literal,handler:"alert('owned')"},
    {html:`<pre>${literal}</pre>`,handler:"alert('owned')"},
    {html:`&lt;${literal.slice(1,-1)}&gt;`,text:literal},
    {html:`<pre>&lt;${literal.slice(1,-1)}&gt;</pre>`,text:literal},
    {html:`&#60;${literal.slice(1,-1)}&#62;`,text:literal},
    {html:'<img src=x onerror="alert(&quot;owned&quot;)">',handler:'alert("owned")'},
  ];
  for(const example of examples){
    const vulnerable=fixture();
    const snapshot=vulnerable.mount({echoHtml:example.html,
      modeCapability:mode('vuln'),captureDom:true});
    assert.equal(valid(capture(snapshot,example.html),example.html,'vuln'),true);
    const images=snapshot.nodes.filter(node=>node.name==='img');
    const handlers=Array.from(snapshot.nodes).flatMap(node=>(node.attributes||[])
      .filter(attribute=>attribute.name==='onerror').map(attribute=>attribute.value));
    if(example.handler){assert.equal(images.length,1);assert.deepEqual(handlers,[example.handler]);}
    else {assert.equal(images.length,0);assert.deepEqual(handlers,[]);
      assert.ok(snapshot.nodes.some(node=>node.type===3&&node.text.includes(example.text)));}
    vulnerable.dom.window.close();
    const fixed=fixture(),fixedSnapshot=fixed.mount({echoHtml:example.html,
      modeCapability:mode('fixed'),captureDom:true});
    assert.equal(valid(capture(fixedSnapshot,example.html),example.html,'fixed'),true);
    assert.equal(fixedSnapshot.nodes[0].name,'pre');
    assert.equal(fixedSnapshot.nodes[1].text,example.html);
    fixed.dom.window.close();
  }
});

test('fixed rendering captures literal text with no fabricated handler, and legacy mount returns no capture',()=>{
  const f=fixture(),html='<img onerror="alert(1)">';
  const snap=f.mount({echoHtml:html,modeCapability:mode('fixed'),captureDom:true});
  const c=capture(snap);
  assert.equal(valid(c,'source','fixed'),true);
  assert.equal(c.snapshot.nodes[0].name,'pre');
  assert.equal(c.snapshot.nodes.length,2);
  assert.equal(c.snapshot.nodes[1].text,html);
  assert.equal(valid(c),false);
  f.dom.window.close();
  const projected=fixture();
  const mounted='<img onerror="globalThis.__proof();alert(1)&amp;&amp;mark()">';
  const projectedSnapshot=projected.mount({echoHtml:mounted,modeCapability:mode('fixed'),captureDom:true});
  const projectedCapture={...capture(projectedSnapshot,html),mountedSourceSha256:sha(mounted)};
  assert.equal(valid(projectedCapture,html,'fixed'),true);
  assert.equal(projectedSnapshot.nodes.length,2);
  assert.equal(projectedSnapshot.nodes[1].text,mounted);
  assert.equal(sha(projectedSnapshot.nodes[1].text),projectedCapture.mountedSourceSha256);
  assert.notEqual(projectedSnapshot.nodes[1].text,html);
  projected.dom.window.close();
  const old=fixture();assert.equal(old.mount({echoHtml:html,modeCapability:mode('vuln')}),undefined);old.dom.window.close();
});

test('capture rejects overflow and missing roots instead of truncating or selecting a spoofed node',()=>{
  const f=fixture();assert.throws(()=>f.mount({echoHtml:'<i></i>'.repeat(129),modeCapability:mode('vuln'),captureDom:true}),/Complete echo DOM/);f.dom.window.close();
  const bytes=fixture();assert.throws(()=>bytes.mount({echoHtml:'\\'.repeat(16300),modeCapability:mode('vuln'),captureDom:true}),/Complete echo DOM/);bytes.dom.window.close();
  const gone=fixture();gone.document.getElementById('sink').remove();
  assert.throws(()=>gone.mount({echoHtml:'<div id="sink">spoof</div>',modeCapability:mode('vuln'),captureDom:true}),/sink unavailable/);gone.dom.window.close();
});

test('validator rejects tampered hashes, extra fields, incomplete tree paths, unknown nodes and over-budget snapshots; JSONB key order survives',()=>{
  const f=fixture();const c=capture(f.mount({echoHtml:'<b>ok</b>',modeCapability:mode('vuln'),captureDom:true}));f.dom.window.close();
  const changes=[x=>x.originalSourceSha256=sha('wrong'),x=>x.snapshotSha256=sha('wrong'),x=>x.extra=true,
    x=>x.snapshot.phase='before-any-execution',x=>x.snapshot.nodes[1].path=[2],x=>x.snapshot.nodes[1].type=7,
    x=>x.snapshot.nodes[2].text='x'.repeat(32769),x=>x.snapshot.nodes[0].name='pre',x=>x.snapshot.nodes[1].attributes.push({name:'x',namespace:null,value:'x',extra:1})];
  for(const change of changes){const bad=structuredClone(c);change(bad);if(bad.snapshotSha256===c.snapshotSha256)bad.snapshotSha256=canonicalDigest(bad.snapshot);assert.equal(valid(bad),false);}
  const reorder=x=>Array.isArray(x)?x.map(reorder):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).reverse().map(k=>[k,reorder(x[k])])):x;
  assert.equal(valid(reorder(c)),true);
});

test('optional runner hook binds actual original/instrumented/projected strings and preserves legacy result shape',async()=>{
  const dom=new JSDOM('');let observed, mountInput, closeCount=0, hookCalls=0, interactions=0, failCapture=false;
  const cdp={on(){},async detach(){},async send(name){return name==='Profiler.takePreciseCoverage'?{result:[]}:{};}};
  const page={on(){},async close(){},async createCDPSession(){return cdp;},async setRequestInterception(){},async setCookie(){},async goto(){},async $$(){interactions++;return [];},
    async evaluate(fn,arg){if(arg?.candidate){observed=vm.runInNewContext('('+fn.toString()+')(arg)',{document:dom.window.document,arg});return observed;}
      return {cookie:'qualification_session=synthetic-fixture-only',elementCount:1,eventAttributes:[]};}};
  const browser={async createBrowserContext(){return {async newPage(){return page;},async close(){closeCount++;}};},async disconnect(){}};
  const runner=createXssBrowserQualification({connectBrowser:async()=>browser,timeoutMs:500,
    clientMount:async(_page,input)=>{mountInput=input;return {owned:'snapshot'};},
    clientDomCapture:(snapshot,hashes)=>{hookCalls++;if(failCapture)throw Error('capture unavailable');assert.deepEqual(snapshot,{owned:'snapshot'});assert.equal(hashes.mountedSourceSha256,sha(observed));return {snapshot,...hashes};}});
  const html="<img src=x onerror='alert(1)'>";
  try {
    const legacy=await runner.qualifyClient(html,{eventSource:html});assert.equal('domCapture' in legacy,false);assert.equal(hookCalls,0);assert.equal('captureDom' in mountInput,false);
    const result=await runner.qualifyClient(html,{eventSource:html,captureDom:true});assert.equal(hookCalls,1);assert.equal(mountInput.captureDom,true);
    assert.equal(result.domCapture.originalSourceSha256,sha(html));assert.notEqual(result.domCapture.instrumentedSourceSha256,sha(html));
    assert.notEqual(result.domCapture.mountedSourceSha256,result.domCapture.instrumentedSourceSha256);
    assert.equal(result.targetEventExecuted,false);assert.equal(result.targetEffectObserved,false);
    assert.equal(closeCount,2);
    const beforeInteractions=interactions;failCapture=true;
    const failed=await runner.qualifyClient(html,{eventSource:html,captureDom:true});
    assert.equal(failed.executed,false);assert.equal('domCapture' in failed,false);
    assert.equal(interactions,beforeInteractions);assert.equal(closeCount,3);
    await assert.rejects(runner.qualifyClient(html,{captureDom:false}),/trusted factory mount/);
  } finally {await runner.close();dom.window.close();}
});

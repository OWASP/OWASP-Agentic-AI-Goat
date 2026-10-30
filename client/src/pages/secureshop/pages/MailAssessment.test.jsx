import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MailAssessment from './MailAssessment';
let mockStandalone = false;
const mockOpenAssessments = jest.fn();
jest.mock('../bridge/assessmentPanelIntent.mjs', () => ({
  isStandaloneShopFrame: () => mockStandalone,
  openStandaloneAssessments: (...args) => mockOpenAssessments(...args),
}));
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => null }));
jest.mock('../utils/shopStorage.mjs', () => ({ shopStorage: {}, flushShopStorage: async () => {} }));
let root,node,controller;
beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT=true;mockStandalone=false;mockOpenAssessments.mockClear();node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);controller=new AbortController(); });
afterEach(async()=>{await act(async()=>root.unmount());node.remove();});
async function render(assess){await act(async()=>root.render(<MailAssessment mail={{assessment:{requestId:'opaque'},assess}} request={()=>({signal:controller.signal,finish(){}})}/>));await act(async()=>node.querySelector('button').click());}
test('unavailable Judge leaves saved reply explicitly saved and offers retry',async()=>{await render(async()=>{throw Error('offline');});expect(node.textContent).toContain('Your reply remains saved');expect(node.querySelector('button').disabled).toBe(false);});
test('disabled objective is separate from no credit and completion',async()=>{await render(async()=>({ok:true,json:async()=>({ok:true,status:'disabled',completed:false})}));expect(node.textContent).toContain('Grading is disabled');expect(node.textContent).not.toContain('Objective completed');});
test('stale session response cannot display a completion',async()=>{let resolve;const pending=new Promise(r=>{resolve=r;});await render(()=>pending);controller.abort();await act(async()=>resolve({ok:true,json:async()=>({ok:true,completed:true})}));expect(node.textContent).not.toContain('Objective completed');});
test('header action keeps save independent from unavailable/disabled grading without reply invocation',async()=>{
 const assess=jest.fn(),assessHeader=jest.fn(async()=>({ok:true,json:async()=>({ok:true,status:'disabled',completed:false})}));await act(async()=>root.render(<MailAssessment kind="header" mail={{headerAssessment:{sendOperationId:'opaque'},assessHeader,assess}} request={()=>({signal:controller.signal,finish(){}})}/>));expect(node.querySelector('button').textContent).toBe('Check saved headers');await act(async()=>node.querySelector('button').click());expect(node.textContent).toContain('Grading is disabled. Your message remains saved.');expect(assess).not.toHaveBeenCalled();expect(node.textContent).not.toContain('Objective completed');
 assessHeader.mockRejectedValueOnce(Error('unavailable'));await act(async()=>node.querySelector('button').click());expect(node.textContent).toContain('Your message remains saved');expect(node.querySelector('button').disabled).toBe(false);
});
test('header display clears prior completion when exact saved reference changes',async()=>{
 const request=()=>({signal:controller.signal,finish(){}}),assessHeader=async()=>({ok:true,json:async()=>({ok:true,completed:true})});
 await act(async()=>root.render(<MailAssessment kind="header" mail={{headerAssessment:{requestId:'r1',sendOperationId:'s1'},assessHeader}} request={request}/>));await act(async()=>node.querySelector('button').click());expect(node.textContent).toContain('Objective completed');
 await act(async()=>root.render(<MailAssessment kind="header" mail={{headerAssessment:{requestId:'r2',sendOperationId:'s2'},assessHeader}} request={request}/>));expect(node.textContent).not.toContain('Objective completed');
});
test('reference replacement ignores paused old AbortError instead of showing retry on new reference',async()=>{
 let reject;const paused=new Promise((_,r)=>{reject=r;}),request=()=>({signal:controller.signal,finish(){}});
 await act(async()=>root.render(<MailAssessment kind="header" mail={{headerAssessment:{requestId:'r1',sendOperationId:'s1'},assessHeader:()=>paused}} request={request}/>));await act(async()=>node.querySelector('button').click());
 await act(async()=>root.render(<MailAssessment kind="header" mail={{headerAssessment:{requestId:'r2',sendOperationId:'s2'},assessHeader:async()=>{}}} request={request}/>));
 await act(async()=>reject(new DOMException('Saved mail reference changed','AbortError')));expect(node.textContent).not.toContain('Grading unavailable');expect(node.querySelector('button').disabled).toBe(false);
});
test('same opaque IDs in another scope cannot retain prior completion or late result',async()=>{
 const reference={requestId:'same-request',sendOperationId:'same-send'},request=()=>({signal:controller.signal,finish(){}});let resolve;const pending=new Promise(r=>{resolve=r;});
 await act(async()=>root.render(<MailAssessment kind="header" mail={{scopeKey:'scope1',headerAssessment:reference,assessHeader:()=>pending}} request={request}/>));await act(async()=>node.querySelector('button').click());
 await act(async()=>root.render(<MailAssessment kind="header" mail={{scopeKey:'scope2',headerAssessment:reference,assessHeader:async()=>{}}} request={request}/>));await act(async()=>resolve({ok:true,json:async()=>({ok:true,completed:true})}));expect(node.textContent).not.toContain('Objective completed');expect(node.querySelector('button').disabled).toBe(false);
});
test('disclosure requires confirmed read, labels manual evidence, and cannot retain stale completion',async()=>{
 const request=()=>({signal:controller.signal,finish(){}}),assessDisclosure=jest.fn(async()=>({ok:true,json:async()=>({ok:true,completed:false,status:'ineligible'})}));
 const reference={requestId:'assessment',readOperationId:'read',confirmed:false};
 await act(async()=>root.render(<MailAssessment kind="disclosure" mail={{disclosureAssessment:reference,assessDisclosure}} request={request}/>));expect(node.querySelector('button')).toBeNull();
 await act(async()=>root.render(<MailAssessment kind="disclosure" mail={{disclosureAssessment:{...reference,confirmed:true},assessDisclosure}} request={request}/>));expect(node.querySelector('button').textContent).toBe('Check saved disclosure');await act(async()=>node.querySelector('button').click());expect(node.textContent).toContain('not eligible');expect(node.textContent).not.toContain('Objective completed');
});

test('browser control is readiness gated and rejects late completion after message replacement', async()=>{
 const reference={requestId:'r',sendOperationId:'s',messageId:1},request=()=>({signal:controller.signal,finish(){}});
 let resolve;const pending=new Promise(r=>{resolve=r;});const mail={browserAssessment:reference,assessBrowser:()=>pending};
 await act(async()=>root.render(<MailAssessment kind="browser" mail={mail} request={request}/>));expect(node.querySelector('button')).toBeNull();
 await act(async()=>root.render(<MailAssessment kind="browser" mail={{...mail,browserAssessmentReady:true}} request={request}/>));expect(node.querySelector('button').textContent).toBe('Check saved message execution');
 await act(async()=>node.querySelector('button').click());
 await act(async()=>root.render(<MailAssessment kind="browser" mail={{...mail,browserAssessmentReady:true,browserAssessment:{...reference,messageId:2}}} request={request}/>));
 await act(async()=>resolve({ok:true,json:async()=>({ok:true,completed:true})}));expect(node.textContent).not.toContain('Objective completed');
});

 test.each([true, false])('unavailable Judge describes retry capability %s without claiming credit', async canRetry => {
  await render(async () => ({ok:true,json:async()=>({ok:true,completed:false,judgment:{verdict:'unavailable',canRetry}})}));
  expect(node.textContent).toContain('Your reply remains saved');
  expect(node.textContent).not.toContain('Objective completed.');
  expect(node.querySelector('button').disabled).toBe(false);
  expect(node.querySelector('button').textContent).toBe('Check saved reply');
  if (canRetry) {
    expect(node.textContent).toContain('use Check saved reply to recover or retry');
    expect(node.textContent).not.toContain('A Judge retry is not available');
  } else {
    expect(node.textContent).toContain('No objective completion was confirmed');
    expect(node.textContent).toContain('A Judge retry is not available');
    expect(node.textContent).toContain('administrator');
    expect(node.textContent).not.toContain('to recover or retry');
  }
 });

test('standalone retained evaluation opens trusted parent recovery without repeating saved mail assessment', async () => {
  mockStandalone = true;
  const evaluationId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
  const assess = jest.fn();
  await act(async () => root.render(<MailAssessment mail={{ assessment: {
    requestId: 'saved', replyOperationId: 'reply', threadId: 2, evaluationId }, assess }}
    request={() => ({ signal: controller.signal, finish() {} })} />));
  const button = node.querySelector('button');
  expect(button.textContent).toBe('Open saved assessments');
  await act(async () => button.click());
  expect(mockOpenAssessments).toHaveBeenCalledWith(evaluationId);
  expect(assess).not.toHaveBeenCalled();
});

test('standalone unavailable grading directs the user to a OWASP AI SecureShop administrator', async () => {
  mockStandalone = true;
  await render(async () => ({ok:true,json:async()=>({ok:true,completed:false,judgment:{verdict:'unavailable',canRetry:false}})}));
  expect(node.textContent).toContain('ask the OWASP AI SecureShop administrator to check the diagnostics');
  expect(node.textContent).not.toContain('workshop administrator');
});

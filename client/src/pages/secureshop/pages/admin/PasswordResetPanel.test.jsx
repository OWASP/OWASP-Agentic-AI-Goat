import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {flushShopStorage} from '../../utils/shopStorage.mjs';
jest.mock('../../utils/shopStorage.mjs',()=>{const actual=jest.requireActual('../../utils/shopStorage.mjs');return{...actual,flushShopStorage:jest.fn(()=>Promise.resolve())};});
import Panel from './PasswordResetPanel.jsx';
let root,node;const secret='SYNTHETIC_PASSWORD_0123456789abcdef0123456789';
const target={id:2,username:'customer',credential_version:'3',authority_version:'4'};
const response=body=>({ok:true,status:200,json:async()=>body});
let operation;
const receipt=()=>({operationId:operation,targetId:2,credentialVersion:'4',authorityVersion:'5',receiptSha256:'a'.repeat(64),expiresAt:new Date(Date.now()+600000).toISOString()});
beforeEach(()=>{flushShopStorage.mockReset();flushShopStorage.mockResolvedValue();localStorage.clear();global.IS_REACT_ACT_ENVIRONMENT=true;node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();});
const render=key=>act(async()=>root.render(<Panel key={key} scopeKey={key} target={target} onClose={()=>{}}/>));
const click=text=>act(async()=>[...node.querySelectorAll('button')].find(b=>b.textContent===text).click());
test('reset metadata, explicit reveal and acknowledgment never persist plaintext',async()=>{
 global.fetch=jest.fn(async(url,options)=>{
  if(url.endsWith('/reset-password')){operation=JSON.parse(options.body).operationId;return response({ok:true,receipt:receipt(),secretAvailable:true});}
  if(url.endsWith('/reveal'))return response({ok:true,receipt:receipt(),temporaryPassword:secret});
  return response({ok:true,receipt:receipt(),secretAvailable:false});
 });
 await render('scope');await click('Confirm password reset');expect(node.textContent).not.toContain(secret);
 await click('Reveal temporary password');expect(node.textContent).toContain(secret);expect(JSON.stringify({...localStorage})).not.toContain(secret);
 await click('Acknowledge and clear password');expect(node.textContent).not.toContain(secret);expect(localStorage.getItem('ss_password_reset_pending')).toBe(null);
});
test('lost reset response uses metadata lookup, never another reset POST',async()=>{
 global.fetch=jest.fn(async(url,options)=>{if(url.endsWith('/reset-password')){operation=JSON.parse(options.body).operationId;throw Error('lost');}return response({ok:true,receipt:receipt(),secretAvailable:true});});
 await render('scope');await click('Confirm password reset');await click('Read reset status');
 expect(fetch.mock.calls.filter(([url])=>url.endsWith('/reset-password'))).toHaveLength(1);expect(node.textContent).toContain('Reveal temporary password');
});
test('held reveal is suppressed after scope replacement',async()=>{
 let finish;global.fetch=jest.fn(async(url,options)=>{if(url.endsWith('/reset-password')){operation=JSON.parse(options.body).operationId;return response({ok:true,receipt:receipt(),secretAvailable:true});}return new Promise(resolve=>{finish=resolve;});});
 await render('scope');await click('Confirm password reset');await click('Reveal temporary password');await render('new-scope');
 await act(async()=>finish(response({ok:true,receipt:receipt(),temporaryPassword:secret})));expect(node.textContent).not.toContain(secret);
});

test('definitive conflict and absent receipt can be explicitly dismissed before a new reset',async()=>{
 let refreshed=0;global.fetch=jest.fn(async(url,options)=>{
  if(url.endsWith('/reset-password')){operation=JSON.parse(options.body).operationId;return{ok:false,status:409};}
  return{ok:false,status:404};
 });
 await act(async()=>root.render(<Panel scopeKey="scope" target={target} onClose={()=>{refreshed++;}}/>));
 await click('Confirm password reset');await click('Read reset status');
 expect(node.textContent).toContain('No committed reset observed');
 await click('Dismiss saved reset and reload');
 expect(localStorage.getItem('ss_password_reset_pending')).toBe(null);expect(refreshed).toBe(1);
 expect(fetch.mock.calls.filter(([url])=>url.endsWith('/reset-password'))).toHaveLength(1);
});
test('replacement administrator session offers local dismissal without receipt or reset replay',async()=>{
 global.fetch=jest.fn(async(url,options)=>{operation=JSON.parse(options.body).operationId;throw Error('unknown');});
 await render('original-session');await click('Confirm password reset');await render('replacement-session');
 expect(node.textContent).toContain('outcome is unknown');expect(node.textContent).not.toContain('Read reset status');
 await click('Dismiss saved reset and reload');expect(localStorage.getItem('ss_password_reset_pending')).toBe(null);expect(fetch).toHaveBeenCalledTimes(1);
});


test('late old storage failure cannot erase a new scope pending operation',async()=>{
 let rejectOld;flushShopStorage.mockImplementationOnce(()=>new Promise((resolve,reject)=>{rejectOld=reject;}));
 global.fetch=jest.fn(async()=>{throw Error('new response lost');});
 await render('old-scope');await click('Confirm password reset');
 await render('new-scope');await click('Dismiss saved reset and reload');
 await click('Confirm password reset');
 const saved=localStorage.getItem('ss_password_reset_pending');expect(JSON.parse(saved).scopeKey).toBe('new-scope');
 await act(async()=>rejectOld(Error('old storage failed')));
 expect(localStorage.getItem('ss_password_reset_pending')).toBe(saved);expect(fetch).toHaveBeenCalledTimes(1);
});

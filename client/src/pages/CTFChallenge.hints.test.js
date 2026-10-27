jest.mock('../context/AuthContext', () => { const user = { id: 1 }; return { useAuth: () => ({ user }) }; });
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import axios from 'axios';
import CTFChallenge from './CTFChallenge';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));

const stage = {
  id: 9,
  stage_number: 1,
  stage_name: 'Reload fixture',
  stage_description: 'Controlled stage',
  difficulty: 'easy',
  ai_guardian_name: 'Fixture Guardian',
  level_score: 100,
  adaptive_mode: 'none',
};

async function flush() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}
function reactHandler(element,name){const props=element[Object.keys(element).find(key=>key.startsWith('__reactProps$'))];expect(typeof props?.[name]).toBe('function');return props[name];}
async function mountReadyHint(){
 axios.post.mockResolvedValueOnce({data:{stage,attemptsSoFar:3,hintsAvailable:true,purchasedHints:[],hintsUsed:0,hintPenaltyTotal:0}});
 axios.get.mockResolvedValueOnce({data:{config:{ctf_hint_gating_attempts:'3',ctf_hint_cost_1:'10'}}});
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));
 await flush();return{node,root};
}
function openHint(node){act(()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock Hint 1')).click());}
function hintDialog(node){const dialog=node.querySelector('[role="dialog"]');expect(dialog).not.toBeNull();return dialog;}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  Element.prototype.scrollIntoView = jest.fn();
  localStorage.clear();
  localStorage.setItem('token', 'owner-token');
  axios.get.mockReset();
  axios.post.mockReset();
});

afterEach(() => {
  document.body.innerHTML = '';
});

test('renders purchased hint text restored by the authenticated stage start response', async () => {
  axios.post.mockResolvedValue({
    data: {
      stage,
      alreadyStarted: true,
      attemptsSoFar: 4,
      hintsAvailable: true,
      hintsUsed: 2,
      hintPenaltyTotal: 40,
      purchasedHints: ['Owned first hint', 'Owned second hint'],
    },
  });
  axios.get.mockResolvedValue({
    data: {
      config: {
        ctf_hint_gating_attempts: '3',
        ctf_hint_cost_3: '40',
      },
    },
  });

  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => {
    root.render(
      <MemoryRouter
        initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <CTFChallenge />
      </MemoryRouter>,
    );
  });
  await flush();

  expect(axios.post).toHaveBeenCalledWith(
    '/api/ctf/stage/9/start',
    {},
    expect.objectContaining({ headers: { Authorization: 'Bearer owner-token' }, signal: expect.any(AbortSignal) }),
  );
  expect(node.textContent).toContain('Owned first hint');
  expect(node.textContent).toContain('Owned second hint');
  expect(node.textContent).toContain('-40 pts');
  expect(node.textContent).toContain('Unlock Hint 3');
  expect(node.textContent).not.toContain('All hints used.');

  act(() => root.unmount());
});

test('does not retain hint text when a later start response provides no purchased hints', async () => {
  axios.post.mockResolvedValue({
    data: {
      stage,
      alreadyStarted: true,
      attemptsSoFar: 0,
      hintsAvailable: false,
      hintsUsed: 0,
      hintPenaltyTotal: 0,
    },
  });
  axios.get.mockResolvedValue({ data: { config: { ctf_hint_gating_attempts: '3' } } });

  const node = document.createElement('div');
  document.body.appendChild(node);
  const root = createRoot(node);
  act(() => {
    root.render(
      <MemoryRouter
        initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <CTFChallenge />
      </MemoryRouter>,
    );
  });
  await flush();

  expect(node.textContent).not.toContain('Owned first hint');
  expect(node.textContent).toContain('Hints unlock after 3 attempts.');
  act(() => root.unmount());
});

test('pending hint waits for current projection and appends once without duplicate purchase', async () => {
  axios.post.mockResolvedValueOnce({ data: { stage, attemptsSoFar: 3, hintsAvailable: true, purchasedHints: [], hintsUsed: 0, hintPenaltyTotal: 0 } });
  axios.get.mockResolvedValueOnce({ data: { config: { ctf_hint_gating_attempts: '3', ctf_hint_cost_1: '10' } } });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  act(() => root.render(<MemoryRouter initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}><CTFChallenge /></MemoryRouter>));
  await flush();
  act(() => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Unlock Hint 1')).click());
  let finish;
  axios.post.mockResolvedValueOnce({ status: 202, data: { operationId: '11111111-1111-4111-8111-111111111111' } });
  axios.get.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  const confirm = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Unlock (-'));
  act(() => confirm.click()); await flush();
  expect(confirm.disabled).toBe(true); expect(node.textContent).not.toContain('Current purchased hint');
  act(() => confirm.click()); expect(axios.post.mock.calls.filter(([url]) => url.endsWith('/hint'))).toHaveLength(1);
  await act(async () => finish({ status: 200, data: { hint: 'Current purchased hint', hintsUsed: 1, totalPenalty: 10 } }));
  await flush(); expect(node.textContent.split('Current purchased hint')).toHaveLength(2);
  act(() => root.unmount());
});
test('two hint confirmations in one render display one purchased hint',async()=>{
 axios.post.mockResolvedValueOnce({data:{stage,attemptsSoFar:3,hintsAvailable:true,purchasedHints:[],hintsUsed:0,hintPenaltyTotal:0}});
 axios.get.mockResolvedValueOnce({data:{config:{ctf_hint_gating_attempts:'3',ctf_hint_cost_1:'10'}}});
 const node=document.createElement('div');document.body.appendChild(node);const root=createRoot(node);
 act(()=>root.render(<MemoryRouter initialEntries={[{pathname:'/ctf/challenge',state:{stage}}]}><CTFChallenge /></MemoryRouter>));
 await flush();
 act(()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock Hint 1')).click());
 const confirm=[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-'));
 axios.post.mockResolvedValue({data:{hint:'One purchased hint',hintsUsed:1,totalPenalty:10}});
 await act(async()=>{confirm.click();confirm.click();});await flush();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(1);
 expect(node.textContent.split('One purchased hint')).toHaveLength(2);
 act(()=>root.unmount());
});
test('canceled hint dialog cannot be purchased by its retained confirmation',async()=>{
 const {node,root}=await mountReadyHint();openHint(node);
 const dialog=hintDialog(node);
 const confirm=reactHandler([...dialog.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')),'onClick');
 act(()=>[...dialog.querySelectorAll('button')].find(button=>button.textContent==='Cancel').click());
 expect(node.querySelector('[role="dialog"]')).toBeNull();
 axios.post.mockResolvedValue({data:{hint:'stale purchased hint',hintsUsed:1,totalPenalty:10}});
 act(()=>{void confirm();});await flush();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(0);
 expect(node.textContent).not.toContain('stale purchased hint');
 act(()=>root.unmount());
});
test('old confirmation cannot purchase a newly staged hint dialog',async()=>{
 const {node,root}=await mountReadyHint();openHint(node);
 const oldDialog=hintDialog(node);
 const oldConfirm=reactHandler([...oldDialog.querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')),'onClick');
 act(()=>[...oldDialog.querySelectorAll('button')].find(button=>button.textContent==='Cancel').click());
 openHint(node);hintDialog(node);
 axios.post.mockResolvedValue({data:{hint:'current purchased hint',hintsUsed:1,totalPenalty:10}});
 act(()=>{void oldConfirm();});await flush();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(0);
 expect(hintDialog(node)).not.toBeNull();
 await act(async()=>[...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).click());await flush();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(1);
 expect(node.textContent.split('current purchased hint')).toHaveLength(2);
 act(()=>root.unmount());
});
test('retained cancel and backdrop handlers cannot close a replacement hint dialog',async()=>{
 const {node,root}=await mountReadyHint();openHint(node);
 const oldDialog=hintDialog(node);
 const oldCancel=reactHandler([...oldDialog.querySelectorAll('button')].find(button=>button.textContent==='Cancel'),'onClick');
 const oldBackdrop=reactHandler(oldDialog.parentElement,'onClick');
 act(()=>[...oldDialog.querySelectorAll('button')].find(button=>button.textContent==='Cancel').click());
 openHint(node);hintDialog(node);
 act(()=>oldCancel());expect(hintDialog(node)).not.toBeNull();
 act(()=>oldBackdrop());expect(hintDialog(node)).not.toBeNull();
 act(()=>root.unmount());
});
test('terminal hint error keeps the same dialog available for an explicit retry',async()=>{
 const alert=jest.spyOn(window,'alert').mockImplementation(()=>{});
 const {node,root}=await mountReadyHint();openHint(node);
 axios.post.mockRejectedValueOnce({response:{status:400,data:{error:'hint rejected'}}});
 await act(async()=>[...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).click());await flush();
 expect(alert).toHaveBeenCalledWith('hint rejected');
 expect(hintDialog(node)).not.toBeNull();
 axios.post.mockResolvedValueOnce({data:{hint:'retried current hint',hintsUsed:1,totalPenalty:10}});
 await act(async()=>[...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).click());await flush();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(2);
 expect(node.textContent.split('retried current hint')).toHaveLength(2);
 act(()=>root.unmount());alert.mockRestore();
});
test('unknown hint outcome holds the dialog until pending result is explicitly dismissed',async()=>{
 const {node,root}=await mountReadyHint();openHint(node);
 const cancel=reactHandler([...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent==='Cancel'),'onClick');
 axios.post.mockRejectedValueOnce(new Error('lost hint response'));
 act(()=>[...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).click());await flush();
 expect(node.textContent).toContain('Outcome unknown');
 act(()=>cancel());expect(hintDialog(node)).not.toBeNull();
 expect(axios.post.mock.calls.filter(([url])=>url.endsWith('/hint'))).toHaveLength(1);
 await act(async()=>[...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent==='Dismiss pending result').click());await flush();
 expect(hintDialog(node)).not.toBeNull();
 expect([...hintDialog(node).querySelectorAll('button')].find(button=>button.textContent.includes('Unlock (-')).disabled).toBe(false);
 act(()=>root.unmount());
});

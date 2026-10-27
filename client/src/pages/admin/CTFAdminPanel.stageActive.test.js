/* eslint-disable testing-library/no-unnecessary-act -- These cases retain exact React event callbacks. */
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { toast } from 'react-toastify';
import CTFAdminPanel from './CTFAdminPanel';

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn(), delete: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { error: jest.fn(), success: jest.fn() } }));

const row = (id, active) => ({ id, stage_number:id, stage_name:id===2?'Target stage':'Sibling stage',
  stage_description:`Description ${id}`, hints:'[]', teaching_objective:'Objective', solution_content:'Solution',
  system_prompt:'POLICY', success_criteria:'CRITERIA', adaptive_mode:'none', level_score:100,
  feedback_mode:'reason', is_active:active });
const button = (node, label) => [...node.querySelectorAll('button')].find(item => item.textContent.trim()===label);
const reactClick = node => node[Object.keys(node).find(key=>key.startsWith('__reactProps$'))].onClick;
const stagesGet = () => axios.get.mock.calls.filter(([url])=>url==='/api/ctf/admin/stages');
const operationGet = id => axios.get.mock.calls.filter(([url])=>url===`/api/ctf/operations/${id}`);
async function flush() { await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();}); }
function targetSwitch(node) {
  const target=[...node.querySelectorAll('tbody tr')].find(tr=>tr.querySelectorAll('td')[1]?.textContent.trim()==='Target stage');
  return target?.querySelector('[role="switch"]');
}
async function mount() {
  const node=document.createElement('div');document.body.appendChild(node);
  const root=createRoot(node);
  await act(async()=>root.render(<CTFAdminPanel/>));await flush();
  await act(async()=>button(node,'Levels').click());await flush();
  return {node,close:async()=>{await act(async()=>root.unmount());node.remove();}};
}
const swap=()=>{
  localStorage.setItem('token','other-admin');
  window.dispatchEvent(new StorageEvent('storage',{key:'token',storageArea:localStorage}));
  localStorage.setItem('token','admin-token');
  window.dispatchEvent(new StorageEvent('storage',{key:'token',storageArea:localStorage}));
};
beforeEach(()=>{
  global.IS_REACT_ACT_ENVIRONMENT=true;
  localStorage.clear();localStorage.setItem('token','admin-token');
  let roster=[row(2,1),row(3,1)];
  axios.get.mockImplementation(url=>Promise.resolve({status:200,data:url==='/api/ctf/admin/stages'?{stages:roster}:{analytics:{}}}));
  axios.put.mockResolvedValue({status:200,data:{message:'Stage updated'}});
  global.__setStageActiveRoster=value=>{roster=value;};
});
afterEach(()=>{localStorage.clear();delete global.__setStageActiveRoster;jest.restoreAllMocks();});

test.each([[1,'Confirm Deactivate',0,'Stage deactivated'],[0,'Confirm Activate',1,'Stage activated']])(
  'active=%s requires Cancel-free confirmation and one exact captured-bearer PUT',async(active,label,next,message)=>{
    global.__setStageActiveRoster([row(2,active),row(3,1)]);
    const mounted=await mount();
    try {
      expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe(String(Boolean(active)));
      await act(async()=>targetSwitch(mounted.node).click());await flush();
      expect(axios.put).not.toHaveBeenCalled();
      expect(mounted.node.querySelector('[role="dialog"]')?.textContent).toContain('Target stage');
      await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),'Cancel').click());await flush();
      expect(axios.put).not.toHaveBeenCalled();
      await act(async()=>targetSwitch(mounted.node).click());await flush();
      global.__setStageActiveRoster([row(2,next),row(3,1)]);
      await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),label).click());await flush();
      expect(axios.put).toHaveBeenCalledTimes(1);
      expect(axios.put).toHaveBeenCalledWith('/api/ctf/admin/stages/2',{is_active:next},expect.objectContaining({headers:{Authorization:'Bearer admin-token'}}));
      expect(stagesGet().length).toBeGreaterThanOrEqual(2);
      expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe(String(Boolean(next)));
      expect(toast.success).toHaveBeenCalledWith(message);
    } finally { await mounted.close(); }
  }
);

test('duplicate retained Confirm synchronously claims one PUT and waits for actual roster GET before changing switch',async()=>{
  let finishPut,finishGet;
  axios.put.mockImplementation(()=>new Promise(resolve=>{finishPut=resolve;}));
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    const retained=reactClick(button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate'));
    act(()=>{retained();retained();});
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('true');
    axios.get.mockImplementation(url=>url==='/api/ctf/admin/stages'?new Promise(resolve=>{finishGet=resolve;}):Promise.resolve({status:200,data:{analytics:{}}}));
    await act(async()=>finishPut({status:200,data:{message:'Stage updated'}}));await flush();
    expect(stagesGet().length).toBe(2);
    expect(toast.success).not.toHaveBeenCalled();
    await act(async()=>finishGet({status:200,data:{stages:[row(2,0),row(3,1)]}}));await flush();
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('false');
    expect(toast.success).toHaveBeenCalledTimes(1);
  } finally { await mounted.close(); }
});

test('storage A→B→A retires retained Confirm before dispatch',async()=>{
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    const retained=reactClick(button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate'));
    act(()=>{swap();retained();});await flush();
    expect(axios.put).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('Refresh receiving a changed active state retires the old staged Confirm with zero PUT',async()=>{
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    const retained=reactClick(button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate'));
    global.__setStageActiveRoster([row(2,0),row(3,1)]);
    await act(async()=>button(mounted.node,'Refresh').click());await flush();
    expect(mounted.node.querySelector('[role="dialog"]')).toBeNull();
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('false');
    await act(async()=>{await retained();});await flush();
    expect(axios.put).not.toHaveBeenCalled();
    expect(toast.success).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

test('202 confirmation recovers only by same-ID GET, never resubmits, then refreshes roster',async()=>{
  const operationId='11111111-1111-4111-8111-111111111111';
  axios.put.mockResolvedValue({status:202,data:{pending:true,operationId}});
  let roster=[row(2,1),row(3,1)];
  axios.get.mockImplementation(url=>{
    if(url===`/api/ctf/operations/${operationId}`){roster=[row(2,0),row(3,1)];return Promise.resolve({status:200,data:{message:'Stage updated'}});}
    return Promise.resolve({status:200,data:url==='/api/ctf/admin/stages'?{stages:roster}:{analytics:{}}});
  });
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate').click());await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(operationGet(operationId)).toHaveLength(1);
    expect(stagesGet().length).toBeGreaterThanOrEqual(2);
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('false');
  } finally { await mounted.close(); }
});

test('lost acknowledgement parks unknown outcome without retry or claiming a failed mutation',async()=>{
  axios.put.mockRejectedValue(new Error('connection lost'));
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate').click());await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(mounted.node.textContent).toContain('Outcome unknown');
    expect(toast.success).not.toHaveBeenCalled();expect(toast.error).not.toHaveBeenCalled();
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('true');
  } finally { await mounted.close(); }
});

test('committed PUT followed by failed roster GET reports refresh failure without retry or false mutation verdict',async()=>{
  axios.put.mockImplementation(()=>{
    axios.get.mockImplementation(url=>url==='/api/ctf/admin/stages'
      ?Promise.reject({response:{status:503,data:{error:'Failed to load stages'}}})
      :Promise.resolve({status:200,data:{analytics:{}}}));
    return Promise.resolve({status:200,data:{message:'Stage updated'}});
  });
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate').click());await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(stagesGet().length).toBe(2);
    expect(targetSwitch(mounted.node).getAttribute('aria-checked')).toBe('true');
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalledWith('Failed to load stages');
    expect(toast.error).not.toHaveBeenCalledWith('Failed to toggle stage');
  } finally { await mounted.close(); }
});

test('late completion after authority retirement cannot publish success, error, or stale roster',async()=>{
  let finishPut;
  axios.put.mockImplementation(()=>new Promise(resolve=>{finishPut=resolve;}));
  const mounted=await mount();
  try {
    await act(async()=>targetSwitch(mounted.node).click());await flush();
    await act(async()=>button(mounted.node.querySelector('[role="dialog"]'),'Confirm Deactivate').click());await flush();
    act(()=>swap());await flush();
    const getsBefore=stagesGet().length;
    await act(async()=>finishPut({status:200,data:{message:'Stage updated'}}));await flush();
    expect(axios.put).toHaveBeenCalledTimes(1);
    expect(stagesGet()).toHaveLength(getsBefore);
    expect(toast.success).not.toHaveBeenCalled();expect(toast.error).not.toHaveBeenCalled();
  } finally { await mounted.close(); }
});

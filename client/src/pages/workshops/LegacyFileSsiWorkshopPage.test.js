import React,{act,useState} from 'react';
import {createRoot} from 'react-dom/client';
import axios from 'axios';
import LegacyFileSsiWorkshopPage from './LegacyFileSsiWorkshopPage';

let mockUser={id:1};
const mockRegisterReconciler=jest.fn(()=>()=>{});
jest.mock('axios',()=>({get:jest.fn(),post:jest.fn()}));
jest.mock('../../context/AuthContext',()=>({useAuth:()=>({user:mockUser})}));
jest.mock('../../context/WorkshopConfigContext',()=>({useWorkshopConfig:()=>({registerReconciler:mockRegisterReconciler})}));
jest.mock('./LegacyFileSsiWorkshop',()=>({__esModule:true,default:({snapshot,onAttempt,onReset,onModeChange,onRefresh})=>{
 const [error,setError]=useState('');
 const invoke=fn=>Promise.resolve().then(fn).catch(e=>setError(e.message));
 return <div data-testid="legacy-page">
  <span data-testid="snapshot">{snapshot?.objectives?.[0]?.label||'loading'}</span>
  <span data-testid="objectives">{snapshot?.objectives?.map(objective=>objective.id).join(',')||''}</span>
  {error&&<span data-testid="child-error">{error}</span>}
  <button type="button" onClick={()=>invoke(onRefresh)}>refresh</button>
  <button type="button" onClick={()=>invoke(onReset)}>reset</button>
  <button type="button" onClick={()=>invoke(()=>onAttempt({objectiveId:'path_traversal',input:'owned'}))}>attempt</button>
  <button type="button" onClick={()=>invoke(()=>onModeChange('fixed'))}>mode</button>
 </div>;
}}));

globalThis.IS_REACT_ACT_ENVIRONMENT=true;

const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const data=label=>({data:{challenges:[{workshopKey:'legacy_sensitive_file_ssi',showHints:false,showSolutions:false,objectives:[{id:'path_traversal',label}]}],content:{}}});
const modeData=()=>({data:{success:true,effectiveMode:'vuln',selectableModes:['vuln','fixed'],scope:{kind:'file_ssi_workflow',id:'legacy_sensitive_file_ssi'}}});
const flush=async()=>{await act(async()=>{await Promise.resolve();await Promise.resolve();await Promise.resolve();});};

let root,node;
beforeEach(()=>{mockUser={id:1};mockRegisterReconciler.mockClear();localStorage.clear();localStorage.setItem('token','token-a');axios.get.mockReset();axios.get.mockImplementation(url=>url.endsWith('/mode')?Promise.resolve(modeData()):Promise.resolve(data('current')));axios.post.mockReset();node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);});
afterEach(()=>{act(()=>root.unmount());node.remove();});

test('retired snapshot cannot replace the replacement session projection',async()=>{
 const first=deferred(),second=deferred();axios.get.mockReset();axios.get.mockReturnValueOnce(first.promise).mockResolvedValueOnce(modeData()).mockReturnValueOnce(second.promise).mockResolvedValueOnce(modeData());
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));
 mockUser={id:2};localStorage.setItem('token','token-b');
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));
 first.resolve(data('old user'));await flush();expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('loading');
 second.resolve(data('new user'));await flush();expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('new user');
 expect(axios.get.mock.calls[0][1].headers.Authorization).toBe('Bearer token-a');
 expect(axios.get.mock.calls[2][1].headers.Authorization).toBe('Bearer token-b');
});

test('token replacement retires a request even before the auth context rerenders',async()=>{
 const pending=deferred();axios.get.mockReset();axios.get.mockReturnValueOnce(pending.promise).mockResolvedValueOnce(modeData());
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));
 localStorage.setItem('token','token-b');pending.resolve(data('stale token'));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('loading');
});

test('retired reset cannot update the replacement page and pins each session request',async()=>{
 axios.get.mockResolvedValue(data('current'));
 const oldReset=deferred();axios.post.mockReturnValueOnce(oldReset.promise).mockResolvedValue({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());
 mockUser={id:2};localStorage.setItem('token','token-b');
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 oldReset.resolve({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});await flush();
 expect(node.querySelector('[data-testid="child-error"]')).toBeNull();
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());await flush();
 expect(axios.post.mock.calls[0][2].headers.Authorization).toBe('Bearer token-a');
 expect(axios.post.mock.calls[1][2].headers.Authorization).toBe('Bearer token-b');
 expect(axios.post.mock.calls[0][2].signal.aborted).toBe(true);
});

test('same-session uncertain reset reuses its operation id for retry',async()=>{
 axios.get.mockResolvedValue(data('current'));const failed=deferred();
 axios.post.mockReturnValueOnce(failed.promise).mockResolvedValue({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());failed.reject(new Error('uncertain'));await flush();
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());await flush();
 const first=axios.post.mock.calls[0][2].headers['x-reset-operation-id'];const second=axios.post.mock.calls[1][2].headers['x-reset-operation-id'];
 expect(first).toBe(second);expect(first).toMatch(/^[0-9a-f-]{36}$/);
});

test('same-tick reset entry admits one mutation and rejects the duplicate',async()=>{
 axios.get.mockResolvedValue(data('current'));const pending=deferred();
 axios.post.mockReturnValueOnce(pending.promise);
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>{const button=node.querySelector('button:nth-of-type(2)');button.click();button.click();});await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);expect(node.querySelector('[data-testid="child-error"]').textContent).toContain('already in progress');
 pending.resolve({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});await flush();
});

test('unmount aborts pending page-owned requests',async()=>{
 const pending=deferred();axios.get.mockReturnValue(pending.promise);
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));
 const signal=axios.get.mock.calls[0][1].signal;act(()=>root.unmount());
 expect(signal.aborted).toBe(true);pending.resolve(data('ignored'));await flush();
});

test('StrictMode effect replay retires the first request and keeps the replacement result',async()=>{
 const first=deferred();axios.get.mockReset();axios.get.mockReturnValueOnce(first.promise).mockResolvedValueOnce(modeData()).mockResolvedValueOnce(data('strict current')).mockResolvedValueOnce(modeData());
 await act(async()=>root.render(<React.StrictMode><LegacyFileSsiWorkshopPage/></React.StrictMode>));
 first.resolve(data('retired strict'));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('strict current');
});


test('live token replacement prevents stale handlers from dispatching reads or mutations',async()=>{
 axios.get.mockResolvedValue(data('current'));
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 localStorage.setItem('token','token-b');
 await act(async()=>{for(const button of node.querySelectorAll('button'))button.click();});await flush();
 expect(axios.get).toHaveBeenCalledTimes(2);expect(axios.post).not.toHaveBeenCalled();
 expect(node.querySelector('[data-testid="child-error"]').textContent).toContain('Retired File and SSI session');
});

test('storage disconnect blocks dispatch without leaving a mutation stuck busy',async()=>{
 axios.get.mockResolvedValue(data('current'));axios.post.mockResolvedValue({data:{success:true,response:'owned result'}});
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 const getItem=jest.spyOn(Storage.prototype,'getItem').mockImplementation(()=>{throw new Error('storage unavailable');});
 try{await act(async()=>node.querySelector('button:nth-of-type(3)').click());await flush();expect(axios.post).not.toHaveBeenCalled();}
 finally{getItem.mockRestore();}
 await act(async()=>node.querySelector('button:nth-of-type(3)').click());await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);
});

test('a refresh begun before reset cannot overwrite the post-reset projection',async()=>{
 const oldRead=deferred(),reset=deferred();
 axios.get.mockReset();axios.get.mockResolvedValueOnce(data('initial')).mockResolvedValueOnce(modeData()).mockReturnValueOnce(oldRead.promise).mockResolvedValueOnce(modeData()).mockResolvedValueOnce(data('after reset')).mockResolvedValueOnce(modeData());
 axios.post.mockReturnValue(reset.promise);
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>node.querySelector('button:nth-of-type(1)').click());
 const staleSignal=axios.get.mock.calls[2][1].signal;
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());expect(staleSignal.aborted).toBe(true);
 reset.resolve({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});await flush();
 await act(async()=>node.querySelector('button:nth-of-type(1)').click());await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('after reset');
 oldRead.resolve(data('before reset'));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('after reset');
});

test('mode change shares the existing session and mutation fence',async()=>{
 axios.get.mockResolvedValue(data('current'));const pending=deferred();axios.post.mockReturnValueOnce(pending.promise);
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>{const buttons=node.querySelectorAll('button');buttons[3].click();buttons[2].click();});await flush();
 expect(axios.post).toHaveBeenCalledTimes(1);expect(axios.post.mock.calls[0][0]).toBe('/api/sensitive-info/canonical-agent/mode');expect(axios.post.mock.calls[0][1]).toEqual({mode:'fixed'});
 expect(node.querySelector('[data-testid="child-error"]').textContent).toContain('already in progress');pending.resolve({data:{success:true,effectiveMode:'fixed'}});await flush();
});

test('admin revision reconciles enabled objectives and instructor labels without a page remount',async()=>{
 let state=data('Original label');
 axios.get.mockImplementation(url=>Promise.resolve(url.endsWith('/mode')?modeData():state));
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('Original label');
 expect(node.querySelector('[data-testid="objectives"]').textContent).toBe('path_traversal');
 state={data:{challenges:[{workshopKey:'legacy_sensitive_file_ssi',showHints:false,showSolutions:false,
  objectives:[{id:'ssi_injection',label:'Instructor edited SSI'}]}],content:{}}};
 await act(async()=>mockRegisterReconciler.mock.calls.at(-1)[0](2,{}));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('Instructor edited SSI');
 expect(node.querySelector('[data-testid="objectives"]').textContent).toBe('ssi_injection');
});

test('failed background revision retains last-good objectives and retries after a later revision',async()=>{
 let state=data('Last good');
 axios.get.mockImplementation(url=>url.endsWith('/mode')?Promise.resolve(modeData()):state instanceof Error?Promise.reject(state):Promise.resolve(state));
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 state=new Error('controlled outage');let failed;
 await act(async()=>{try{await mockRegisterReconciler.mock.calls.at(-1)[0](3,{});}catch(error){failed=error;}});
 expect(failed).toBe(state);
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('Last good');
 expect(node.querySelector('[role="alert"]')?.textContent).toContain('last known state');
 state=data('After retry');
 await act(async()=>mockRegisterReconciler.mock.calls.at(-1)[0](4,{}));await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('After retry');
 expect(node.querySelector('[role="alert"]')).toBeNull();
});

test('superseded revision read does not acknowledge stale data after owner replacement',async()=>{
 const pending=deferred();let next=data('Owned initial');
 axios.get.mockImplementation(url=>url.endsWith('/mode')?Promise.resolve(modeData()):next instanceof Promise?next:Promise.resolve(next));
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 next=pending.promise;
 const reconcile=mockRegisterReconciler.mock.calls.at(-1)[0];
 let settled;
 let refresh;
 await act(async()=>{refresh=reconcile(5,{});await Promise.resolve();});
 mockUser={id:2};localStorage.setItem('token','token-b');next=data('Replacement owner');
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>{pending.resolve(data('Retired owner'));try{settled=await refresh;}catch(error){settled=error;}});await flush();
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('Replacement owner');
 expect(settled).toBe(false);
});

test('aborted revision request on the same owner is not acknowledged',async()=>{
 const pending=deferred();let next=data('Initial');
 axios.get.mockImplementation(url=>url.endsWith('/mode')?Promise.resolve(modeData()):next instanceof Promise?next:Promise.resolve(next));
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 next=pending.promise;const abort=new AbortController();
 let refresh;await act(async()=>{refresh=mockRegisterReconciler.mock.calls.at(-1)[0](7,{signal:abort.signal});await Promise.resolve();});
 abort.abort();pending.resolve(data('Stale'));let failed;
 await act(async()=>{try{await refresh;}catch(error){failed=error;}});
 expect(failed?.message).toContain('superseded');
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('Initial');
});

test('revision overlapping an in-flight mutation does not acknowledge stale state',async()=>{
 const pending=deferred();axios.post.mockReturnValue(pending.promise);
 await act(async()=>root.render(<LegacyFileSsiWorkshopPage/>));await flush();
 await act(async()=>node.querySelector('button:nth-of-type(2)').click());
 let failed;await act(async()=>{try{await mockRegisterReconciler.mock.calls.at(-1)[0](8,{});}catch(error){failed=error;}});
 expect(failed?.message).toContain('overlaps a mutation');
 expect(node.querySelector('[data-testid="snapshot"]').textContent).toBe('current');
 pending.resolve({data:{success:true,reset:{operationId:'fixture',fromGeneration:0,toGeneration:1}}});await flush();
});

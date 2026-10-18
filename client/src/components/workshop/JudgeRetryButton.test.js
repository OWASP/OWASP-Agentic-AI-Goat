import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import JudgeRetryButton from './JudgeRetryButton';

jest.mock('axios', () => ({ post: jest.fn() }));

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  axios.post.mockReset();
});

test('retry posts only the durable evaluation ID and never replays chat evidence', async () => {
  const onResult = jest.fn();
  axios.post.mockResolvedValue({ data: { judgment: { verdict: 'pass', canRetry: false }, completed: true } });
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<JudgeRetryButton evaluationId="eval-123" canRetry onResult={onResult} />));
  await act(async () => node.querySelector('button').click());
  expect(axios.post).toHaveBeenCalledWith('/api/agent-runs/judgments/eval-123/retry', {}, { signal: expect.any(AbortSignal) });
  expect(JSON.stringify(axios.post.mock.calls[0])).not.toMatch(/prompt|message|tool|evidence/i);
  expect(onResult).toHaveBeenCalledWith(expect.objectContaining({ completed: true }), { signal: expect.any(AbortSignal) });
  expect(node.textContent).toContain('Evaluation retried');
  act(() => root.unmount());
});

test('does not render without the server canRetry capability', () => {
  const node = document.createElement('div'); const root = createRoot(node);
  act(() => root.render(<JudgeRetryButton evaluationId="eval-123" canRetry={false} />));
  expect(node.querySelector('button')).toBeNull();
  act(() => root.unmount());
});

test('shows a bounded server error and allows retry when the server keeps the capability', async () => {
  axios.post.mockRejectedValue({ response: { data: { message: 'Judge is temporarily unavailable.', canRetry: true } } });
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<JudgeRetryButton evaluationId="eval-456" canRetry />));
  await act(async () => node.querySelector('button').click());
  expect(node.textContent).toContain('Judge is temporarily unavailable.');
  expect(node.querySelector('button').disabled).toBe(false);
  act(() => root.unmount());
});

test('aborts and ignores an in-flight retry when reset removes the feedback message', async () => {
  let resolveRetry;
  axios.post.mockImplementation((_url, _body, options) => new Promise(resolve => {
    resolveRetry = resolve;
    expect(options.signal.aborted).toBe(false);
  }));
  const onResult = jest.fn();
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<JudgeRetryButton evaluationId="eval-reset" canRetry onResult={onResult} />));
  await act(async () => node.querySelector('button').click());
  const signal = axios.post.mock.calls[0][2].signal;
  act(() => root.render(<></>));
  expect(signal.aborted).toBe(true);
  await act(async () => resolveRetry({ data: { judgment: { verdict: 'pass' }, completed: true } }));
  expect(onResult).not.toHaveBeenCalled();
  act(() => root.unmount());
});


test('retry remains usable after React StrictMode replays effect setup', async () => {
  const onResult = jest.fn();
  axios.post.mockResolvedValue({ data: { judgment: { verdict: 'pass' }, completed: true } });
  const node = document.createElement('div'); const root = createRoot(node);
  await act(async () => root.render(<React.StrictMode><JudgeRetryButton evaluationId="eval-strict" canRetry onResult={onResult} /></React.StrictMode>));
  await act(async () => node.querySelector('button').click());
  expect(onResult).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Evaluation retried');
  act(() => root.unmount());
});

test.each([409, 503])('HTTP %s denial is unavailable, never a successful evaluation', async status => {
  axios.post.mockRejectedValue({ response: { status, data: { error: 'Grading retry unavailable', canRetry: false } } });
  const onResult = jest.fn();
  const node = document.createElement('div'); const root = createRoot(node);
  try {
    await act(async () => root.render(<JudgeRetryButton evaluationId="eval-denied" canRetry onResult={onResult} />));
    await act(async () => node.querySelector('button').click());
    expect(node.querySelector('button').textContent).toBe('Retry unavailable');
    expect(node.querySelector('button').disabled).toBe(true);
    expect(node.textContent).not.toContain('Evaluation retried');
    expect(node.querySelector('[role="status"]').textContent).toBe('Grading retry unavailable');
    expect(onResult).not.toHaveBeenCalled();
    await act(async () => node.querySelector('button').click());
    expect(axios.post).toHaveBeenCalledTimes(1);
  } finally { act(() => root.unmount()); }
});

test('successful unavailable receipt is forwarded unchanged without inventing credit', async () => {
  const data = { judgment: { verdict: 'unavailable', canRetry: false }, completed: false };
  axios.post.mockResolvedValue({ data });
  const onResult = jest.fn();
  const node = document.createElement('div'); const root = createRoot(node);
  try {
    await act(async () => root.render(<JudgeRetryButton evaluationId="eval-no-credit" canRetry onResult={onResult} />));
    await act(async () => node.querySelector('button').click());
    expect(node.querySelector('button').textContent).toBe('Evaluation retried');
    expect(onResult).toHaveBeenCalledTimes(1);
    expect(onResult.mock.calls[0][0]).toBe(data);
    expect(data.completed).toBe(false);
    expect(data.judgment.verdict).toBe('unavailable');
  } finally { act(() => root.unmount()); }
});

test.each([{evaluationId:'eval-new',canRetry:true},{evaluationId:'eval-old',canRetry:false}].flatMap(props=>[false,true].map(reject=>({...props,reject}))))('changed retry capability retires the pending request: %j', async next => {
  let resolveRetry, rejectRetry;
  axios.post.mockImplementation(()=>new Promise((resolve,reject)=>{resolveRetry=resolve;rejectRetry=reject;}));
  const onResult=jest.fn(),node=document.createElement('div'),root=createRoot(node);
  try {
    await act(async()=>root.render(<JudgeRetryButton evaluationId="eval-old" canRetry onResult={onResult} />));
    await act(async()=>node.querySelector('button').click());
    const signal=axios.post.mock.calls[0][2].signal;
    await act(async()=>root.render(<JudgeRetryButton {...next} onResult={onResult} />));
    expect(signal.aborted).toBe(true);
    await act(async()=>{if(next.reject)rejectRetry({response:{data:{canRetry:false,error:'old failure'}}});else resolveRetry({data:{completed:true}});});
    expect(onResult).not.toHaveBeenCalled();
    if(next.canRetry){expect(node.querySelector('button').disabled).toBe(false);expect(node.textContent).toBe('Retry evaluation');}
    else expect(node.querySelector('button')).toBeNull();
  } finally {act(()=>root.unmount());}
});

test('new evaluation starts ready after a previous evaluation completed', async () => {
  axios.post.mockResolvedValue({data:{completed:false,judgment:{verdict:'inconclusive'}}});
  const node=document.createElement('div'),root=createRoot(node),onResult=jest.fn();
  try {
    await act(async()=>root.render(<JudgeRetryButton evaluationId="first" canRetry onResult={onResult}/>));
    await act(async()=>node.querySelector('button').click());
    expect(node.textContent).toBe('Evaluation retried');
    await act(async()=>root.render(<JudgeRetryButton evaluationId="second" canRetry onResult={onResult}/>));
    expect(node.textContent).toBe('Retry evaluation');expect(node.querySelector('button').disabled).toBe(false);
    await act(async()=>node.querySelector('button').click());
    expect(axios.post.mock.calls.map(call=>call[0])).toEqual(['/api/agent-runs/judgments/first/retry','/api/agent-runs/judgments/second/retry']);
    expect(onResult).toHaveBeenCalledTimes(2);
  } finally {act(()=>root.unmount());}
});

test.each(['evaluation','unmount'])('successful callback remains cancellable by %s lifetime retirement', async change => {
  axios.post.mockResolvedValue({data:{completed:false}});
  let resolveRefresh,callbackSignal;
  const onResult=jest.fn((_data,{signal})=>{callbackSignal=signal;return new Promise(resolve=>{resolveRefresh=resolve;});});
  const node=document.createElement('div'),root=createRoot(node);let unmounted=false;
  try {
    await act(async()=>root.render(<JudgeRetryButton evaluationId="old" canRetry onResult={onResult}/>));
    await act(async()=>node.querySelector('button').click());
    expect(callbackSignal.aborted).toBe(false);
    if(change==='unmount'){act(()=>root.unmount());unmounted=true;}
    else await act(async()=>root.render(<JudgeRetryButton evaluationId="new" canRetry onResult={onResult}/>));
    expect(callbackSignal.aborted).toBe(true);
    await act(async()=>resolveRefresh());
    if(!unmounted)expect(node.textContent).toBe('Retry evaluation');
  } finally {if(!unmounted)act(()=>root.unmount());}
});

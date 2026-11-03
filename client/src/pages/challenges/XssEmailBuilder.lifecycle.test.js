import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import XssEmailBuilder from './XssEmailBuilder';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn(), put: jest.fn() }));
let mockOwnerId = 41;
let mockBuilderMode = 'vuln';
jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: mockOwnerId } }) }));
jest.mock('../../components/HintPanel', () => () => null);

const objectives = [1, 2, 3, 4].map(level => ({ id: `xss_email_level_${level}`, label: `Edited level ${level}`, hintVisible: true }));
const progress = { data: { progress: objectives.map(item => ({ objective_id: item.id, completed: false })) } };
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
const confirmReset = async () => {
  const dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog).toBeTruthy();
  await act(async () => [...dialog.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm reset').click());
  await flush();
};

function renderBuilder() {
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={objectives} onProgressChange={() => {}} />));
  return { node, root };
}

beforeEach(() => {
  mockOwnerId = 41;
  mockBuilderMode = 'vuln';
  axios.get.mockImplementation(url => url === '/api/xss-email/mode' ? Promise.resolve({ data: { mode: mockBuilderMode, effectiveMode: mockBuilderMode, scope: { kind: 'workshop', id: 'xss_email_builder' } } }) : url.includes('/profile/') ? Promise.resolve({ data: { profile: {} } }) : url.includes('/templates/') ? Promise.resolve({ data: { templates: [{ id: 't1', subject: 'Hello' }] } }) : Promise.resolve({ data: { ...progress.data, canonical: { objectives: objectives.map(item => ({ id: item.id, label: item.label, completed: false })) } } }));
  axios.put.mockResolvedValue({ data: { profile: {} } });
  axios.post.mockImplementation(url => url.includes('/preview/render')
    ? Promise.resolve({ data: '<!-- attacker pre-head --><script>alert(1)</script><html><head></head><body>teaching</body></html>' })
    : Promise.resolve({ data: { template: { id: 't1', subject: 'Hello', html_content: '<script>alert(1)</script>' }, completedLevels: [], judgments: [] } }));
});

afterEach(() => { document.body.innerHTML = ''; jest.clearAllMocks(); });

test('builder preview adds restrictive CSP and keeps the HTML in an opaque sandbox', async () => {
  const { node, root } = renderBuilder(); await flush();
  const select = node.querySelector('select[aria-label="Saved template"]');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, 't1'); select.dispatchEvent(new Event('change', { bubbles: true })); });
  const previewButton = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Preview'));
  await act(async () => previewButton.click()); await flush();
  const frame = node.querySelector('iframe');
  expect(frame.getAttribute('sandbox')).toContain('allow-scripts');
  expect(frame.srcdoc).toContain("default-src 'none'");
  expect(frame.srcdoc.indexOf("default-src 'none'")).toBeLessThan(frame.srcdoc.indexOf('attacker pre-head'));
  act(() => root.unmount());
});

test('fixed builder preview is inert text and mode switch keeps saved templates', async () => {
  const original = axios.post.getMockImplementation();
  axios.post.mockImplementation((url,body,options) => url === '/api/xss-email/mode'
    ? (mockBuilderMode = body.mode, Promise.resolve({ data: { mode: body.mode, effectiveMode: body.mode, scope: { kind: 'workshop', id: 'xss_email_builder' } } }))
    : url.includes('/preview/render') && mockBuilderMode === 'fixed'
      ? Promise.resolve({ data: '&lt;script&gt;alert(1)&lt;/script&gt;' })
      : original(url,body,options));
  const {node,root}=renderBuilder();await flush();
  const select=node.querySelector('select[aria-label="Saved template"]');
  await act(async()=>{select.value='t1';select.dispatchEvent(new Event('change',{bubbles:true}));});
  await act(async()=>[...node.querySelectorAll('[data-workshop-mode-control] button')].find(button=>button.textContent.trim()==='Fixed').click());
  expect(node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('fixed');
  await act(async()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Preview')).click());await flush();
  expect(node.querySelector('iframe')).toBeNull();
  expect(node.querySelector('[data-testid="fixed-email-preview"]').textContent).toContain('&lt;script&gt;');
  expect(node.querySelectorAll('select[aria-label="Saved template"] option')).toHaveLength(2);
  act(()=>root.unmount());
});

test('builder mode stamp suppresses a late vulnerable generation after switching to fixed', async () => {
  let resolveGenerate;
  axios.post.mockImplementation((url,body) => url === '/api/xss-email/mode'
    ? (mockBuilderMode=body.mode, Promise.resolve({data:{mode:body.mode,effectiveMode:body.mode,scope:{kind:'workshop',id:'xss_email_builder'}}}))
    : url.includes('/generate') ? new Promise(resolve=>{resolveGenerate=resolve;}) : Promise.resolve({data:{}}));
  const {node,root}=renderBuilder();await flush();
  await act(async()=>[...node.querySelectorAll('button')].find(button=>button.textContent.includes('Generate')).click());
  await act(async()=>[...node.querySelectorAll('[data-workshop-mode-control] button')].find(button=>button.textContent.trim()==='Fixed').click());
  await act(async()=>resolveGenerate({data:{mode:'vuln',template:{id:'late-vuln',subject:'Late vulnerable template'},completedLevels:[1]}}));
  expect(node.textContent).not.toContain('Late vulnerable template');
  expect(node.querySelectorAll('select[aria-label="Saved template"] option')).toHaveLength(2);
  expect(node.querySelector('[data-workshop-mode-control]').getAttribute('data-workshop-mode')).toBe('fixed');
  act(()=>root.unmount());
});

test('unmount aborts outstanding requests and stale generation cannot update the unmounted builder', async () => {
  let resolveGenerate;
  axios.post.mockImplementation(url => url.includes('/generate') ? new Promise(resolve => { resolveGenerate = resolve; }) : Promise.resolve({ data: {} }));
  const { node, root } = renderBuilder(); await flush();
  const generate = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate'));
  await act(async () => generate.click());
  act(() => root.unmount());
  resolveGenerate?.({ data: { template: { id: 'late' }, completedLevels: [] } });
  await flush();
  expect(document.body.textContent).not.toContain('late');
});

test('reset supersedes a pending generation and StrictMode mounts cleanly', async () => {
  let resolveGenerate;
  axios.post.mockImplementation(url => url.includes('/generate') ? new Promise(resolve => { resolveGenerate = resolve; }) : Promise.resolve({ data: { success: true } }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => root.render(<React.StrictMode><XssEmailBuilder objectives={objectives} onProgressChange={() => {}} /></React.StrictMode>)); await flush();
  const generate = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate'));
  await act(async () => generate.click());
  const reset = [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset builder'));
  await act(async () => reset.click());
  await confirmReset();
  resolveGenerate?.({ data: { template: { id: 'stale' } } }); await flush();
  expect(node.textContent).not.toContain('stale');
  act(() => root.unmount());
});

test('builder reset confirmation can cancel and retries the same operation after a failed request', async () => {
  let rejectReset;
  let resetCalls = 0;
  const originalPost = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, body, options) => {
    if (url !== '/api/xss-email/challenge/reset') return originalPost(url, body, options);
    resetCalls += 1;
    return resetCalls === 1
      ? new Promise((_resolve, reject) => { rejectReset = reject; })
      : Promise.resolve({ data: { success: true } });
  });
  const onProgressChange = jest.fn();
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={objectives} onProgressChange={onProgressChange} />));
  await flush(); onProgressChange.mockClear();

  const reset = () => [...node.querySelectorAll('button')]
    .find(button => button.textContent.includes('Reset builder'));
  act(() => reset().click());
  expect(document.querySelector('[role="alertdialog"]').textContent).toContain('Saved profile inputs');
  expect(resetCalls).toBe(0);
  act(() => [...document.querySelector('[role="alertdialog"]').querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(resetCalls).toBe(0);

  act(() => reset().click());
  await confirmReset();
  expect(resetCalls).toBe(1);
  const firstBody = axios.post.mock.calls.find(([url]) => url === '/api/xss-email/challenge/reset')[1];
  expect(firstBody.operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  let dialog = document.querySelector('[role="alertdialog"]');
  expect([...dialog.querySelectorAll('button')].every(button => button.disabled)).toBe(true);
  await act(async () => rejectReset({ response: { data: { error: 'Reset unavailable' } } }));
  await flush();
  dialog = document.querySelector('[role="alertdialog"]');
  expect(dialog.textContent).toContain('Reset unavailable');
  expect(onProgressChange).not.toHaveBeenCalledWith([]);

  await confirmReset();
  expect(resetCalls).toBe(2);
  const resetBodies = axios.post.mock.calls.filter(([url]) => url === '/api/xss-email/challenge/reset').map(([, body]) => body);
  expect(resetBodies[1].operationId).toBe(firstBody.operationId);
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  expect(onProgressChange).toHaveBeenCalledWith([]);
  act(() => root.unmount());
});

test('builder renders only explicitly enabled catalog objectives', () => {
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={objectives.slice(0, 2)} onProgressChange={() => {}} />));
  expect(node.querySelectorAll('select[aria-label="Email builder objective"] option')).toHaveLength(2);
  expect(node.querySelector('select[aria-label="Email builder objective"] option').textContent).toBe('Edited level 1');
  act(() => root.unmount());
});

test('revoked solution gate cannot publish a late solution response', async () => {
  let resolveSolution;
  const withSolution = objectives.map(item => ({ ...item, solutionVisible: true }));
  axios.get.mockImplementation(url => url.includes('/solutions/xss-email-builder/')
    ? new Promise(resolve => { resolveSolution = resolve; })
    : url.includes('/profile/') ? Promise.resolve({ data: { profile: {} } })
      : url.includes('/templates/') ? Promise.resolve({ data: { templates: [] } }) : Promise.resolve(progress));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => root.render(<XssEmailBuilder objectives={withSolution} onProgressChange={() => {}} />)); await flush();
  await act(async () => node.querySelector('[data-testid="solution-button-xss_email_level_1"]').click());
  await act(async () => root.render(<XssEmailBuilder objectives={objectives} onProgressChange={() => {}} />));
  resolveSolution?.({ data: { solution: { title: 'late revoked solution' } } }); await flush();
  expect(node.textContent).not.toContain('late revoked solution');
  act(() => root.unmount());
});

test('builder solution uses shared help while hint gating remains independent', async () => {
  const withSolution = objectives.map(item => ({ ...item, hintVisible: false, solutionVisible: true }));
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/solutions/xss-email-builder/xss_email_level_1'
    ? Promise.resolve({ data: { solution: {
      title: 'Instructor solution', description: 'Observed outcome',
      explanation: 'Explain the evidence', approach: 'Try the bounded route',
      examples: [{ prompt: 'Owned example prompt', explanation: 'Expected result' }],
    } } }) : originalGet(url));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={withSolution} onProgressChange={() => {}} />));
  await flush();
  expect(node.querySelector('[data-testid="hint-button-xss_email_level_1"]')).toBeNull();
  act(() => node.querySelector('[data-testid="solution-button-xss_email_level_1"]').click());
  await flush();
  const dialog = document.querySelector('[data-testid="objective-help-modal"]');
  expect(dialog.dataset.helpKind).toBe('solution');
  expect(dialog.textContent).toContain('Instructor solution');
  expect(dialog.textContent).toContain('Observed outcome');
  expect(dialog.textContent).toContain('Explain the evidence');
  expect(dialog.textContent).toContain('Try the bounded route');
  expect(dialog.textContent).toContain('Expected result');
  act(() => dialog.querySelector('[data-testid="solution-example"] button').click());
  expect(node.querySelector('textarea[aria-label="Generation prompt"]').value).toBe('Owned example prompt');
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  act(() => root.unmount());
});

test('effective objective fallback invalidates a pending generation', async () => {
  let resolveGenerate;
  axios.post.mockImplementation(url => url.includes('/generate') ? new Promise(resolve => { resolveGenerate = resolve; }) : Promise.resolve({ data: {} }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => root.render(<XssEmailBuilder objectives={objectives.slice(0, 2)} onProgressChange={() => {}} />)); await flush();
  const objective = node.querySelector('select[aria-label="Email builder objective"]');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(objective, '2'); objective.dispatchEvent(new Event('change', { bubbles: true })); });
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate')).click());
  await act(async () => root.render(<XssEmailBuilder objectives={objectives.slice(0, 1)} onProgressChange={() => {}} />));
  resolveGenerate?.({ data: { template: { id: 'late-fallback', subject: 'late fallback' }, completedLevels: [] } }); await flush();
  expect(node.textContent).not.toContain('late fallback');
  act(() => root.unmount());
});

test('initial profile load cannot overwrite a newer saved profile', async () => {
  let resolveProfile;
  axios.get.mockImplementation(url => url.includes('/profile/')
    ? new Promise(resolve => { resolveProfile = resolve; })
    : url.includes('/templates/') ? Promise.resolve({ data: { templates: [] } }) : Promise.resolve(progress));
  axios.put.mockResolvedValue({ data: { profile: { full_name: 'new profile' } } });
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => root.render(<XssEmailBuilder objectives={objectives} onProgressChange={() => {}} />));
  const field = node.querySelector('input[aria-label="full_name"]');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, 'new profile'); field.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Save profile')).click());
  resolveProfile?.({ data: { profile: { full_name: 'old profile' } } }); await flush();
  expect(node.querySelector('input[aria-label="full_name"]').value).toBe('new profile');
  act(() => root.unmount());
});


test('owner switch aborts the previous generation and never publishes its template or credit', async () => {
  let resolveGenerate, oldSignal;
  axios.post.mockImplementation((url, _body, options) => new Promise(resolve => { resolveGenerate = resolve; oldSignal = options.signal; }));
  const { node, root } = renderBuilder(); await flush();
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate')).click());
  mockOwnerId = 42;
  const onProgressChange = jest.fn();
  await act(async () => root.render(<XssEmailBuilder objectives={objectives} onProgressChange={onProgressChange} />)); await flush();
  expect(oldSignal.aborted).toBe(true);
  expect(axios.get).toHaveBeenCalledWith('/api/xss-email/profile/42', expect.any(Object));
  onProgressChange.mockClear();
  await act(async () => resolveGenerate({ data: { template: { id: 'old-owner', subject: 'PRIVATE OLD OWNER' }, completedLevels: [1] } }));
  expect(node.textContent).not.toContain('PRIVATE OLD OWNER');
  expect(onProgressChange).not.toHaveBeenCalled();
  expect([...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate')).disabled).toBe(false);
  act(() => root.unmount());
});

test('owner switch retires a confirmed builder reset without clearing the replacement owner', async () => {
  let resolveReset;
  let resetSignal;
  const originalPost = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, body, options) => url === '/api/xss-email/challenge/reset'
    ? new Promise(resolve => { resolveReset = resolve; resetSignal = options.signal; })
    : originalPost(url, body, options));
  const { node, root } = renderBuilder(); await flush();
  act(() => [...node.querySelectorAll('button')]
    .find(button => button.textContent.includes('Reset builder')).click());
  await confirmReset();
  expect(resetSignal).toBeTruthy();

  mockOwnerId = 42;
  const replacementProgress = jest.fn();
  await act(async () => root.render(<XssEmailBuilder objectives={objectives}
    onProgressChange={replacementProgress} />));
  await flush();
  expect(resetSignal.aborted).toBe(true);
  expect(document.querySelector('[role="alertdialog"]')).toBeNull();
  replacementProgress.mockClear();
  await act(async () => resolveReset({ data: { success: true } }));
  expect(node.querySelectorAll('select[aria-label="Saved template"] option')).toHaveLength(2);
  expect(replacementProgress).not.toHaveBeenCalledWith([]);
  act(() => root.unmount());
});

test('reset aborts a pending preview and its late HTML cannot replace the cleared state', async () => {
  let resolvePreview, previewSignal;
  axios.post.mockImplementation((url, _body, options) => url.includes('/preview/render')
    ? new Promise(resolve => { resolvePreview = resolve; previewSignal = options.signal; })
    : Promise.resolve({ data: { success: true } }));
  const { node, root } = renderBuilder(); await flush();
  const select = node.querySelector('select[aria-label="Saved template"]');
  await act(async () => { select.value = 't1'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Preview')).click());
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Reset builder')).click());
  await confirmReset();
  expect(previewSignal.aborted).toBe(true);
  await act(async () => resolvePreview({ data: '<script>alert(99)</script>' }));
  expect(node.querySelector('iframe')).toBeNull();
  expect(node.querySelectorAll('select[aria-label="Saved template"] option')).toHaveLength(1);
  expect([...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate')).disabled).toBe(false);
  act(() => root.unmount());
});

test('builder progress counts enabled catalog membership and retains canonical help titles', async () => {
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url.includes('/challenge/progress/')
    ? Promise.resolve({ data: { canonical: { objectives: [
      { id: 'xss_email_level_1', completed: true },
      { id: 'xss_email_level_4', completed: true },
    ] } } })
    : url.includes('/solutions/xss-email-builder/')
      ? Promise.resolve({ data: { solution: { title: 'Authored solution heading', description: 'Solution details' } } })
      : originalGet(url));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={objectives.slice(0, 2).map(item => ({ ...item, solutionVisible: true }))} />));
  await flush();
  expect(node.textContent).toContain('1 of 2 objectives completed');
  const bar = node.querySelector('[role="progressbar"]');
  expect(bar.getAttribute('aria-valuenow')).toBe('1');
  expect(bar.getAttribute('aria-valuemax')).toBe('2');
  act(() => node.querySelector('[data-testid="solution-button-xss_email_level_1"]').click());
  await flush();
  const dialog = document.querySelector('[data-testid="objective-help-modal"]');
  expect(dialog.querySelector('h2').textContent).toContain('Edited level 1');
  expect(dialog.textContent).toContain('Authored solution heading');
  act(() => root.unmount());
});

test('builder keeps execution disabled until its mode is confirmed', async () => {
  let resolveMode;
  const originalGet = axios.get.getMockImplementation();
  axios.get.mockImplementation(url => url === '/api/xss-email/mode'
    ? new Promise(resolve => { resolveMode = resolve; }) : originalGet(url));
  const { node, root } = renderBuilder(); await flush();
  const generate = () => [...node.querySelectorAll('button')].find(button => button.textContent.includes('Generate'));
  expect(generate().disabled).toBe(true);
  expect(node.textContent).toContain('Checking builder mode');
  await act(async () => resolveMode({ data: { effectiveMode: 'vuln', scope: { id: 'xss_email_builder' } } }));
  expect(generate().disabled).toBe(false);
  act(() => root.unmount());
});

test('inactive builder retains its draft and closes portal help', async () => {
  const withSolution = objectives.map(item => ({ ...item, solutionVisible: true }));
  const node = document.createElement('div'); document.body.appendChild(node);
  const root = createRoot(node);
  act(() => root.render(<XssEmailBuilder objectives={withSolution} active />));
  await flush();
  const prompt = node.querySelector('textarea[aria-label="Generation prompt"]');
  act(() => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(prompt, 'My retained builder draft');
    prompt.dispatchEvent(new Event('input', { bubbles: true }));
    node.querySelector('[data-testid="solution-button-xss_email_level_1"]').click();
  });
  await flush();
  expect(document.querySelector('[data-testid="objective-help-modal"]')).not.toBeNull();
  act(() => root.render(<XssEmailBuilder objectives={withSolution} active={false} />));
  expect(document.querySelector('[data-testid="objective-help-modal"]')).toBeNull();
  act(() => root.render(<XssEmailBuilder objectives={withSolution} active />));
  expect(node.querySelector('textarea[aria-label="Generation prompt"]').value).toBe('My retained builder draft');
  act(() => root.unmount());
});

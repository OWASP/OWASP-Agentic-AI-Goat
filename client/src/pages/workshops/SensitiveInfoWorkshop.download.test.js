jest.mock('../../context/AuthContext', () => ({ useAuth: () => ({ user: { id: 1 } }) }));
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { createHash } from 'node:crypto';
import axios from 'axios';
import { toast } from 'react-toastify';
import SensitiveInfoWorkshop from './SensitiveInfoWorkshop';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
let mockAdditionalObjective = false;
jest.mock('axios', () => ({ get: jest.fn(), post: jest.fn() }));
jest.mock('react-toastify', () => ({ toast: { info: jest.fn(), error: jest.fn(), success: jest.fn() } }));
jest.mock('../../components/VulnerabilityTemplate', () => ({ children }) => <div>{children}</div>);
jest.mock('../../hooks/useWorkshopHeartbeat', () => () => {});
jest.mock('../../hooks/useChangePolling', () => () => {});
jest.mock('../../components/HintPanel', () => () => null);
jest.mock('../../context/WorkshopConfigContext', () => ({ useWorkshopConfig: () => ({ revision: 1, snapshot: { exercises: { sensitive_info_disclosure: { isVisible: true, objectives: { admin_dl_backup: { isVisible: true }, ...(mockAdditionalObjective ? { admin_backup: { isVisible: true } } : {}) } } } } }) }));
const content = '[\n  {"name":"José 雪", "balance":42}\n]\n';
const digest = value => createHash('sha256').update(value).digest('hex');
const successfulTool = () => ({ name: 'admin_download_backup', success: true,
  result: 'Formatted prose deliberately differs from the artifact.', resourceContent: content,
  resourceMetadata: { kind: 'backup_downloaded', requestedPath: '/var/app/data/backups/owned_backup.bak', byteLength: Buffer.byteLength(content), contentSha256: digest(content) } });
async function mountAndSend(toolCalls, mode = 'vulnerable') {
  axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/mode') ? { mode } : url.includes('/progress/') ? { progress: [] } : url.endsWith('/llm-status') ? { available: false } : { objectives: {} } }));
  axios.post.mockImplementation(url => Promise.resolve({ data: url.endsWith('/chat') ? { success: true, response: 'Voici votre fichier.', toolCalls, newlyCompletedObjectives: [] } : { success: true } }));
  const node = document.createElement('div'); document.body.appendChild(node); const root = createRoot(node);
  await act(async () => { root.render(<SensitiveInfoWorkshop />); });
  expect(node.textContent).toContain(mode === 'fixed' ? 'Fixed Mode' : 'Vulnerable Mode');
  const input = node.querySelector('textarea');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, 'Récupérez le fichier créé précédemment.');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => { input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
  return { node, close: () => { act(() => root.unmount()); node.remove(); } };
}
test('successful non-English request downloads exact owned Unicode bytes and trailing LF', async () => {
  let blob; URL.createObjectURL = jest.fn(value => { blob = value; return 'blob:owned'; }); URL.revokeObjectURL = jest.fn();
  const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  const view = await mountAndSend([successfulTool()]);
  try {
    const button = [...view.node.querySelectorAll('button')].find(b => b.textContent.includes('Download owned_backup.bak'));
    expect(button).toBeDefined(); act(() => button.click());
    const bytes = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(Buffer.from(reader.result)); reader.onerror = reject; reader.readAsArrayBuffer(blob); });
    expect(bytes.equals(Buffer.from(content))).toBe(true); expect(bytes.length).toBe(successfulTool().resourceMetadata.byteLength);
    expect(digest(bytes)).toBe(successfulTool().resourceMetadata.contentSha256);
    expect(click.mock.instances[0].download).toBe('owned_backup.bak'); expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:owned');
  } finally { view.close(); click.mockRestore(); }
});
test.each([
  ['failed tool', [{ ...successfulTool(), success: false }]],
  ['unrelated tool', [{ ...successfulTool(), name: 'admin_create_backup' }]],
  ['prose-only result', [{ name: 'admin_download_backup', success: true, result: 'Downloading backup from: /var/app/data/backups/owned_backup.bak\n\n[]' }]],
  ['wrong metadata kind', [{ ...successfulTool(), resourceMetadata: { ...successfulTool().resourceMetadata, kind: 'backup_created' } }]],
])('%s cannot produce a download button', async (_name, tools) => {
  const view = await mountAndSend(tools);
  try { expect(view.node.textContent).not.toContain('Download owned_backup.bak'); expect(view.node.textContent).not.toContain('Download backup.bak'); }
  finally { view.close(); }
});

const pdfBytes = Buffer.from('%PDF-1.4\n% controlled binary: \x00\xff\n%%EOF\n', 'latin1');
const statementTool = () => ({ name: 'download_statement', success: true, isPDF: true,
  result: 'Statement generated.', pdfFilename: 'statement_FF-001_2024.pdf', pdfContent: pdfBytes.toString('base64') });
test.each(['fixed', 'vulnerable'])('%s successful statement downloads exact PDF bytes', async mode => {
  let blob; URL.createObjectURL = jest.fn(value => { blob = value; return 'blob:statement'; }); URL.revokeObjectURL = jest.fn();
  const click = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  const view = await mountAndSend([statementTool()], mode);
  try {
    const button = [...view.node.querySelectorAll('button')].find(b => b.textContent.includes('Download statement_FF-001_2024.pdf'));
    expect(button).toBeDefined(); act(() => button.click());
    const bytes = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(Buffer.from(reader.result)); reader.onerror = reject; reader.readAsArrayBuffer(blob); });
    expect(bytes.equals(pdfBytes)).toBe(true); expect(blob.type).toBe('application/pdf');
    expect(click.mock.instances[0].download).toBe('statement_FF-001_2024.pdf');
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:statement');
  } finally { view.close(); click.mockRestore(); }
});
test.each([
  ['failed', { ...statementTool(), success: false }],
  ['unrelated', { ...statementTool(), name: 'admin_read_logs' }],
  ['false PDF marker', { ...statementTool(), isPDF: false }],
  ['prose-only', { name: 'download_statement', success: true, result: 'Download statement_FF-001_2024.pdf' }],
  ['malformed base64', { ...statementTool(), pdfContent: '%not-base64' }],
  ['missing bytes', { ...statementTool(), pdfContent: '' }],
  ['path filename', { ...statementTool(), pdfFilename: '../statement_FF-001_2024.pdf' }],
])('%s statement result cannot expose a PDF download', async (_name, tool) => {
  const view = await mountAndSend([tool]);
  try { expect([...view.node.querySelectorAll('button')].some(b => b.textContent.includes('Download '))).toBe(false); }
  finally { view.close(); }
});

describe('pending FinFlow chat lifecycle', () => {
  let node; let root;
  const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
  const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });
  async function mount(strict = false, progress = []) {
    axios.get.mockImplementation(url => Promise.resolve({ data: url.endsWith('/mode') ? { mode: 'vulnerable' } : url.includes('/progress/') ? { progress } : { objectives: {} } }));
    axios.post.mockReset(); axios.post.mockResolvedValue({ data: { success: true } });
    node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node);
    await act(async () => root.render(strict ? <React.StrictMode><SensitiveInfoWorkshop /></React.StrictMode> : <SensitiveInfoWorkshop />));
  }
  async function send(value = 'Download current artifact') {
    const input = node.querySelector('textarea');
    act(() => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); });
    await act(async () => input.closest('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  }
  const button = text => [...node.querySelectorAll('button')].find(b => b.textContent.trim() === text);
  async function confirmProgressReset() {
    act(() => button('Reset objective progress').click());
    const dialog = document.querySelector('[role="alertdialog"]');
    expect(dialog).not.toBeNull();
    act(() => [...dialog.querySelectorAll('button')].find(b => b.textContent === 'Confirm reset').click());
    await flush();
  }
  const result = tool => ({ data: { response: 'Old artifact response', toolCalls: [tool], newlyCompletedObjectives: [] } });
  afterEach(() => { mockAdditionalObjective = false; if (root) act(() => root.unmount()); root = null; node?.remove(); });
  test.each([['backup', successfulTool], ['PDF', statementTool]])('conversation reset rejects late %s download and old history', async (_kind, tool) => {
    await mount(); const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise);
    await send('Old request');
    act(() => button('Reset conversation').click());
    pending.resolve(result(tool())); await flush();
    expect(node.textContent).not.toContain('Old artifact response');
    expect(node.textContent).not.toContain('Download owned_backup.bak');
    expect(node.textContent).not.toContain('Download statement_FF-001_2024.pdf');
    axios.post.mockResolvedValueOnce({ data: { response: 'Current response', toolCalls: [], newlyCompletedObjectives: [] } });
    await send('New request');
    const calls = axios.post.mock.calls.filter(([url]) => url.endsWith('/chat'));
    expect(calls).toHaveLength(2); expect(calls[1][1].conversationHistory).toEqual([]);
  });
  test('objective selection rejects old response while current request retains loading and download', async () => {
    await mount(); const old = deferred(); axios.post.mockReturnValueOnce(old.promise); await send('Old request');
    act(() => [...node.querySelectorAll('button')].find(b => b.textContent.includes('Admin Exploitation')).click());
    act(() => node.querySelector('.obj-name').closest('.obj-name').parentElement.parentElement.click());
    const current = deferred(); axios.post.mockReturnValueOnce(current.promise); await send('Current request');
    old.resolve(result(successfulTool())); await flush();
    expect(node.textContent).not.toContain('Old artifact response');
    expect(node.querySelector('textarea').disabled).toBe(true);
    current.resolve({ data: { response: 'Current download', toolCalls: [statementTool()], newlyCompletedObjectives: [] } }); await flush();
    expect(node.textContent).toContain('Download statement_FF-001_2024.pdf');
    expect(node.querySelector('textarea').disabled).toBe(false);
  });
  test('failed progress reset keeps existing transcript but retires pending artifact response', async () => {
    await mount(); axios.post.mockResolvedValueOnce({ data: { response: 'Existing transcript', toolCalls: [], newlyCompletedObjectives: [] } }); await send();
    const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send('Pending old request');
    axios.post.mockRejectedValueOnce(new Error('controlled reset failure'));
    await confirmProgressReset();
    expect(node.textContent).toContain('Existing transcript');
    expect(toast.error).toHaveBeenCalledWith('Reset failed');
    pending.resolve(result(successfulTool())); await flush();
    expect(node.textContent).not.toContain('Download owned_backup.bak');
    expect(node.textContent).not.toContain('Old artifact response');
    axios.post.mockResolvedValueOnce({ data: { response: 'Retry after reset failure', toolCalls: [], newlyCompletedObjectives: [] } }); await send();
    expect(node.textContent).toContain('Retry after reset failure');
  });
  test('failed completion refresh does not auto-advance back to an already completed objective', async () => {
    mockAdditionalObjective = true;
    await mount(false, [{ id: 'admin_backup', completed: true }, { id: 'admin_dl_backup', completed: false }]);
    act(() => [...node.querySelectorAll('button')].find(b => b.textContent.includes('Admin Exploitation')).click());
    act(() => [...node.querySelectorAll('.obj-name')].find(e => e.textContent === 'Download DB Backup').parentElement.parentElement.click());
    axios.get.mockRejectedValueOnce(new Error('Completion refresh unavailable'));
    axios.post.mockResolvedValueOnce({ data: { response: 'Completed download', toolCalls: [], newlyCompletedObjectives: ['admin_dl_backup'] } });
    await send('Complete selected objective');
    axios.post.mockResolvedValueOnce({ data: { response: 'Next request', toolCalls: [], newlyCompletedObjectives: [] } });
    await send('Keep selected objective');
    const calls = axios.post.mock.calls.filter(([url]) => url.endsWith('/chat'));
    expect(calls.at(-1)[1].objectiveId).toBe('admin_dl_backup');
  });
  test.each(['failed', 'successful', 'superseded'])('confirmed reset progress read %s never reuses obsolete conversation', async outcome => {
    await mount();
    axios.post.mockResolvedValueOnce({ data: { response: 'Existing transcript', toolCalls: [], newlyCompletedObjectives: [] } });
    await send('Prior conversation');
    toast.success.mockClear(); toast.error.mockClear();
    const pending = deferred();
    if (outcome === 'failed') axios.get.mockRejectedValueOnce(new Error('Progress unavailable'));
    else if (outcome === 'superseded') axios.get.mockReturnValueOnce(pending.promise);
    await confirmProgressReset();
    if (outcome === 'superseded') {
      act(() => button('Refresh').click()); await flush();
      pending.resolve({ data: { progress: [] } }); await flush();
    }
    expect(node.textContent).not.toContain('Existing transcript');
    if (outcome === 'successful') expect(toast.success).toHaveBeenCalledWith('Progress reset');
    else {
      expect(toast.success).not.toHaveBeenCalledWith('Progress reset');
      expect(toast.error).toHaveBeenCalledWith('Reset applied, but progress could not be refreshed. Refresh progress to confirm.');
    }
    axios.post.mockResolvedValueOnce({ data: { response: 'New transcript', toolCalls: [], newlyCompletedObjectives: [] } });
    await send('After reset');
    const calls = axios.post.mock.calls.filter(([url]) => url.endsWith('/chat'));
    expect(calls.at(-1)[1].conversationHistory).toEqual([]);
  });
  test.each(['resolve', 'reject'])('unmount suppresses noncooperative late chat %s and grade notices', async settlement => {
    await mount(); const pending = deferred(); axios.post.mockReturnValueOnce(pending.promise); await send();
    const request = axios.post.mock.calls.find(([url]) => url.endsWith('/chat'));
    act(() => root.unmount()); root = null;
    expect(request[2].signal.aborted).toBe(true);
    toast.success.mockClear(); toast.error.mockClear(); axios.get.mockClear();
    if (settlement === 'resolve') pending.resolve({ data: { ...result(successfulTool()).data, newlyCompletedObjectives: ['admin_dl_backup'] } });
    else pending.reject(new Error('late failure'));
    await flush();
    expect(toast.success).not.toHaveBeenCalled(); expect(toast.error).not.toHaveBeenCalled();
    expect(axios.get).not.toHaveBeenCalled();
  });
  test('StrictMode permits current successful structured download', async () => {
    await mount(true); axios.post.mockResolvedValueOnce(result(successfulTool())); await send();
    expect(node.textContent).toContain('Download owned_backup.bak');
  });

});

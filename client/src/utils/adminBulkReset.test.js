import {runAdminBulkReset} from './adminBulkReset';
const ID = '11111111-1111-4111-8111-111111111111';
const key = 'dvaia:admin-reset:7:workshop:csrf_workshop';
function fixture() {
  return {api: {get: jest.fn().mockResolvedValue({data: {success: true, operations: []}}),
    post: jest.fn().mockResolvedValue({data: {success: true}})}, actorId: 7, token: 'controlled',
    workshopKey: 'csrf_workshop', isCurrent: () => true};
}
afterEach(() => sessionStorage.clear());
test('lost success retains the original ID through retry and clears only after confirmed success', async () => {
  const f = fixture();
  f.api.post.mockRejectedValueOnce(new Error('network'));
  await expect(runAdminBulkReset(f)).rejects.toThrow('network');
  const saved = sessionStorage.getItem(key);
  expect(saved).toMatch(/^[a-f0-9-]{36}$/);
  await runAdminBulkReset(f);
  expect(f.api.post.mock.calls[1][2].headers['x-reset-operation-id']).toBe(saved);
  expect(sessionStorage.getItem(key)).toBeNull();
});
test('another browser discovers and resumes the original server cohort', async () => {
  const f = fixture();
  f.api.get.mockResolvedValue({data: {success: true, operations: [
    {operationId: ID, requestKind: 'workshop', workshopKeys: ['csrf_workshop']} ]}});
  await runAdminBulkReset(f);
  expect(f.api.get.mock.calls[0][1].params).toEqual({requestKind: 'workshop', workshopKey: 'csrf_workshop'});
  expect(f.api.post.mock.calls[0][2].headers['x-reset-operation-id']).toBe(ID);
});
test('all-workshop recovery preserves the password-confirmed endpoint', async () => {
  const f = {...fixture(), workshopKey: undefined, confirmPassword: 'controlled-password'};
  f.api.get.mockResolvedValue({data: {success: true, operations: [{operationId: ID, requestKind: 'all'}]}});
  await runAdminBulkReset(f);
  expect(f.api.get.mock.calls[0][1].params).toEqual({requestKind: 'all'});
  expect(f.api.post).toHaveBeenCalledWith('/api/admin/database/reset',
    {resetType: 'challenges', confirmPassword: 'controlled-password'},
    {headers: {Authorization: 'Bearer controlled', 'x-reset-operation-id': ID}});
});
test('discovery outage cannot start an unjournaled replacement reset', async () => {
  const f = fixture(); f.api.get.mockRejectedValue(new Error('offline'));
  await expect(runAdminBulkReset(f)).rejects.toThrow('offline');
  expect(f.api.post).not.toHaveBeenCalled();
});
test('authority change after discovery prevents mutation', async () => {
  const f = fixture(); let current = true;
  f.isCurrent = () => current;
  f.api.get.mockImplementation(async () => {current = false; return {data: {success: true, operations: []}};});
  await expect(runAdminBulkReset(f)).rejects.toThrow('session changed');
  expect(f.api.post).not.toHaveBeenCalled();
});
test('unavailable durable browser storage prevents effects', async () => {
  const f = fixture(); f.storage = {getItem: () => null, setItem: () => {throw new Error('storage unavailable');}};
  await expect(runAdminBulkReset(f)).rejects.toThrow('storage unavailable');
  expect(f.api.post).not.toHaveBeenCalled();
});
test('application failure and late authority changes preserve recovery state', async () => {
  const f = fixture(); f.api.post.mockResolvedValueOnce({data: {success: false, error: 'pending'}});
  await expect(runAdminBulkReset(f)).rejects.toThrow('pending');
  const saved = sessionStorage.getItem(key);
  let current = true; f.isCurrent = () => current;
  f.api.post.mockImplementation(async () => {current = false; return {data: {success: true}};});
  await expect(runAdminBulkReset(f)).rejects.toThrow('session changed');
  expect(sessionStorage.getItem(key)).toBe(saved);
});
test('same administrator cannot send overlapping operations from this client', async () => {
  const f = fixture(); let release;
  f.api.get.mockImplementationOnce(() => new Promise(resolve => {release = resolve;}));
  const first = runAdminBulkReset(f);
  await expect(runAdminBulkReset({...f, workshopKey: 'mcp_workshop'})).rejects.toThrow('already running');
  release({data: {success: true, operations: []}}); await first;
});
test('failed canonical commit retains operation until mutation and refresh both succeed', async () => {
  const f = fixture(); f.onCommit = jest.fn().mockRejectedValueOnce(new Error('refresh failed'));
  await expect(runAdminBulkReset(f)).rejects.toThrow('refresh failed');
  const saved = sessionStorage.getItem(key);
  await runAdminBulkReset(f);
  expect(f.api.post.mock.calls[1][2].headers['x-reset-operation-id']).toBe(saved);
  expect(f.onCommit).toHaveBeenCalledTimes(2); expect(sessionStorage.getItem(key)).toBeNull();
});

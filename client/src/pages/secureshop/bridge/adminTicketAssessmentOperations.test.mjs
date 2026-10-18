import { compileOperation, matchOperationRequest } from './operations.mjs';
const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const path = '/api/secureshop/admin/tickets/42/assessment';
test('closed admin ticket assessment admits exact ID and body only', () => {
  const post = matchOperationRequest({ pathname: path, method: 'POST', body: { requestId } });
  expect(post.name).toBe('admin.tickets.assess');
  expect(compileOperation(post.name, post.input)).toMatchObject({ path, method: 'POST' });
  const getPath = `${path}/${requestId}`;
  const get = matchOperationRequest({ pathname: getPath, method: 'GET' });
  expect(get.name).toBe('admin.tickets.assessment');
  expect(compileOperation(get.name, get.input)).toMatchObject({ path: getPath, method: 'GET' });
  expect(() => matchOperationRequest({ pathname: path, method: 'POST', body: {
    requestId, ticketBody: 'untrusted source',
  } })).toThrow();
  expect(() => matchOperationRequest({ pathname: getPath, method: 'GET',
    query: { retry: '1' } })).toThrow();
});

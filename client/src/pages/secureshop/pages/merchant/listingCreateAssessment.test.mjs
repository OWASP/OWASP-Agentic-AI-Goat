import { expect, test } from '@jest/globals';
import { assessListingCreate, decodeListingCreateAssessment, readListingCreateAssessment } from './listingCreateAssessment.mjs';
const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const evaluationId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const response = value => ({ ok: true, status: 200, json: async () => value });
const unavailable = { operationId, completed: false, judgment: { verdict: 'unavailable', evaluationId, canRetry: true }, replayed: false };
const pass = { operationId, completed: true, judgment: { verdict: 'pass', evaluationId, canRetry: false }, replayed: false };

test('accepts only the closed operation-bound assessment outcomes', () => {
  expect(decodeListingCreateAssessment({ operationId, completed: false, status: 'unconfirmed', modelEvaluated: false }, operationId))
    .toEqual({ operationId, completed: false, status: 'unconfirmed', modelEvaluated: false });
  expect(decodeListingCreateAssessment(unavailable, operationId)).toEqual(unavailable);
  expect(decodeListingCreateAssessment(pass, operationId)).toEqual(pass);
  expect(() => decodeListingCreateAssessment({ ...unavailable, operationId: evaluationId }, operationId)).toThrow('Saved listing assessment');
  expect(() => decodeListingCreateAssessment({ ...unavailable, extra: true }, operationId)).toThrow('Saved listing assessment');
  for (const malformed of [
    { ...unavailable, judgment: { ...unavailable.judgment, detail: 'not projected' } },
    { ...unavailable, completed: true },
    { ...pass, judgment: { ...pass.judgment, verdict: 'fail' } },
    { ...pass, judgment: { ...pass.judgment, canRetry: true } },
    { ...unavailable, judgment: { ...unavailable.judgment, evaluationId: evaluationId.toUpperCase() } },
  ]) expect(() => decodeListingCreateAssessment(malformed, operationId)).toThrow('Saved listing assessment');
});

test('posts only the original operation ID and reads status without rerunning assessment', async () => {
  const transport = jest.fn(async (url, options = {}) => url.endsWith(`/assessment/${operationId}`)
    ? response(unavailable) : response({ operationId, completed: false, status: 'ineligible', modelEvaluated: false }));
  await expect(assessListingCreate(transport, operationId)).resolves.toMatchObject({ status: 'ineligible' });
  await expect(readListingCreateAssessment(transport, operationId)).resolves.toEqual(unavailable);
  expect(transport.mock.calls[0]).toEqual(['/api/secureshop/agents/merchant/assistant/listing-create/assess', expect.objectContaining({ method: 'POST' })]);
  expect(JSON.parse(transport.mock.calls[0][1].body)).toEqual({ operationId });
  expect(transport.mock.calls[1][1].method).toBe('GET');
});

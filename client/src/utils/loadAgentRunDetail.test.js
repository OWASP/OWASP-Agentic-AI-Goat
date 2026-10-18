import axios from 'axios';
import { loadAgentRunDetail } from './loadAgentRunDetail';
jest.mock('axios');
afterEach(() => jest.resetAllMocks());

test('rejects a repeated cursor instead of looping or reporting a truncated success', async () => {
  axios.get.mockResolvedValue({ data: { events: [{ seq: 100 }], nextCursor: 100 } });
  await expect(loadAgentRunDetail('/api/agent-runs', 'run')).rejects.toThrow('pagination did not advance');
  expect(axios.get).toHaveBeenCalledTimes(2);
});

test('cancellation prevents fetching another timeline page', async () => {
  const controller = new AbortController();
  axios.get.mockImplementation(async () => {
    controller.abort();
    return { data: { events: [{ seq: 100 }], nextCursor: 100 } };
  });
  expect(await loadAgentRunDetail('/api/agent-runs', 'run', controller.signal)).toBeNull();
  expect(axios.get).toHaveBeenCalledTimes(1);
});

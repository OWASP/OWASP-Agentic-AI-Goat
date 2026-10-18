import axios from 'axios';

// The detail endpoint returns only the first page, even for completed runs.
export async function loadAgentRunDetail(endpoint, runId, signal) {
  const url = `${endpoint}/${encodeURIComponent(runId)}`;
  const initial = await axios.get(url, { signal });
  const detail = { ...initial.data, events: [...(initial.data.events || [])] };
  const seen = new Set(detail.events.map(event => event.seq));
  let previousCursor = 0;
  while (detail.nextCursor != null) {
    if (signal?.aborted) return null;
    const cursor = Number(detail.nextCursor);
    if (!Number.isSafeInteger(cursor) || cursor <= previousCursor) {
      throw new Error('Run timeline pagination did not advance.');
    }
    const page = await axios.get(`${url}/events`, { params: { after: cursor, limit: 100 }, signal });
    if (signal?.aborted) return null;
    for (const event of page.data.events || []) {
      if (!seen.has(event.seq)) { detail.events.push(event); seen.add(event.seq); }
    }
    // Retain the detail snapshot's status so polling can refresh its receipts
    // if the run completed while these event pages were being fetched.
    detail.nextCursor = page.data.nextCursor ?? null;
    previousCursor = cursor;
  }
  return detail;
}

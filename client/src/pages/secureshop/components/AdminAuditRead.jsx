import React from 'react';

export default function AdminAuditRead({ read }) {
  if (!read) return null;
  return <section className="ss-card" aria-label="Admin audit activity"
    style={{ padding: 12, marginTop: 10 }}>
    <strong>Recent audit activity</strong>
    {read.events.length === 0 ? <p>No matching events in this saved read.</p>
      : <ol>{read.events.map(item => <li key={item.id}
        style={{ marginTop: 8, overflowWrap: 'anywhere' }}>
        <strong>{item.action}</strong> · {item.outcome}
        <div className="ss-mono">{item.ts} · {item.actor} · {item.store} journal</div>
        <div>Target: {item.target ?? 'None recorded'}</div>
        <details><summary>Event details</summary>
          <div>Source: {item.source_kind} · {item.source_id}</div>
          <div className="ss-mono" style={{ overflowWrap: 'anywhere' }}>Event: {item.event_id}</div>
          <pre style={{ maxHeight: 220, overflow: 'auto', whiteSpace: 'pre-wrap',
            overflowWrap: 'anywhere' }}>{item.params_json}</pre>
        </details>
      </li>)}</ol>}
    <p className="ss-mono">{read.hasMore
      ? read.nextPageAvailable ? 'Older matching events are available.'
        : 'More events may exist, but this read has no next page.'
      : 'No additional events reported for this read.'}</p>
  </section>;
}

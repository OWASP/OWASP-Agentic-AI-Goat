import React from 'react';

export default function MerchantManualSearchCard({ read }) {
  const { result } = read;
  return <section className="ss-card" aria-label="Merchant manual search result"
    style={{ padding: 12, marginTop: 10 }}>
    <strong>Manual sources for {result.product.name}</strong>
    <p className="ss-mono" style={{ overflowWrap: 'anywhere' }}>Question: {result.query}</p>
    {result.count === 0 && <p>No manual sources found.</p>}
    {result.status === 'oversized' && <p>Manual excerpts exceed this chat’s saved read limit.
      No manual answer is verified from this result.</p>}
    {result.sources.length > 0 && <ul style={{ paddingLeft: 18 }}>
      {result.sources.map(source => <li key={`${source.sourceId}:${source.chunkIndex}`}
        style={{ overflowWrap: 'anywhere', marginBottom: 12 }}>
        <strong>{source.filename}</strong> · Chunk {source.chunkIndex + 1}
        <div className="ss-mono">Saved {source.completedAt} · Score {source.score}</div>
        {source.text !== null
          ? <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 320,
            overflow: 'auto', border: '1px solid var(--rule)', borderRadius: 8,
            padding: 12 }}>{source.text}</pre>
          : <p className="ss-mono">Excerpt unavailable here.</p>}
        <details className="ss-mono"><summary>Source verification</summary>
          <div>{source.textBytes} bytes · SHA-256 {source.textSha256}</div>
          <div>Source SHA-256 {source.sourceSha256}</div>
        </details>
      </li>)}
    </ul>}
    {result.hasMore && <p className="ss-mono">More matching manual sources exist beyond these {result.count} results.</p>}
  </section>;
}

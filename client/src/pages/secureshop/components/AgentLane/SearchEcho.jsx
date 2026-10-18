import React from 'react';

const MAX_ECHO_BYTES = 16384;

// The caller supplies the current trusted mode decision. This component only
// renders the already selected, bounded echo_html field.
export default function SearchEcho({ echoHtml, fixed, qualificationRef }) {
  if (typeof echoHtml !== 'string' || !echoHtml.length
      || !echoHtml.isWellFormed() || echoHtml.includes('\0')
      || new TextEncoder().encode(echoHtml).byteLength > MAX_ECHO_BYTES) return null;

  return (
    <section className="ss-sheet__section" aria-label="Reflected preview">
      <div className="ss-sheet__label">Reflected preview (echo_html)</div>
      {fixed
        ? <pre ref={qualificationRef} className="ss-agent-lane__echo" data-testid="hop-echo-html"
            style={{ padding: 12, background: 'var(--paper)', border: '1px solid var(--rule)', whiteSpace: 'pre-wrap' }}>{echoHtml}</pre>
        : <div ref={qualificationRef} className="ss-agent-lane__echo" data-testid="hop-echo-html"
            style={{ padding: 12, background: 'var(--paper)', border: '1px solid var(--rule)' }}
            dangerouslySetInnerHTML={{ __html: echoHtml }} />}
    </section>
  );
}

export { MAX_ECHO_BYTES };

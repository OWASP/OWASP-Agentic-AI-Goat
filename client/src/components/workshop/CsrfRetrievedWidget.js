import React from 'react';

// Managed email execution has already observed and applied its one request.
// Its transcript preview must not replay that request in the learner browser.
// The indirect lesson retains its existing executable widget teaching sink.
export default function CsrfRetrievedWidget({ id, html, browserExecuted = false, renderPolicy = null }) {
  return <iframe title={`rag-widget-${id}`}
    sandbox={browserExecuted || renderPolicy === 'escaped_inert_text' ? '' : 'allow-scripts allow-same-origin'}
    style={{ width: '100%', height: 54, border: 'none', background: '#fff' }}
    srcDoc={`<body style="margin:6px;font:12px system-ui;color:#334155">${html}<div>account-verification widget</div></body>`} />;
}

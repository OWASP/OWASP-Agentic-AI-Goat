import React from 'react';

// The admin detail is the one intentional raw ticket sink. List previews and
// customer confirmation continue to render the same stored bytes as text.
// @intentional-vulnerability xss-stored-ticket
export default function AdminTicketBody({ body, modeCapability }) {
  return modeCapability?.effectiveMode === 'vuln'
    ? <div data-testid="ticket-vulnerable-body" dangerouslySetInnerHTML={{ __html: body }} />
    : <div data-testid="ticket-fixed-body" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
      {body}
    </div>;
}

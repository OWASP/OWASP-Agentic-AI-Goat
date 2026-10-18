import React from 'react';
export default function MailCapabilityStatus({ capabilities }) {
  if (!capabilities) return null;
  const messages = [['actor', 'Auto-reply'], ['judge', 'Grading']].flatMap(([key, label]) => {
    const value = capabilities[key];
    if (!value || value.status === 'available') return [];
    if (value.status === 'configured_unprobed') return [`${label}: cloud provider configured; availability has not been checked.`];
    if (value.status === 'unknown_unprobed') return [`${label}: model availability is unverified.`];
    return [`${label}: model currently unavailable.`];
  });
  if (!messages.length) return null;
  return <div role="status" style={{ fontSize: 12, marginBottom: 8 }}>
    {messages.join(' ')} Saved messages and requests can still be recovered. Try the action again to refresh availability.
  </div>;
}

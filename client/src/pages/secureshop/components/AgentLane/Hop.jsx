import React from 'react';

export default function Hop({ hop, index, onOpen, fullParams = false }) {
  const dot = hop.status === 'in-flight' ? 'ss-dot--amber'
    : hop.status === 'error' ? 'ss-dot--rust'
    : hop.policyViolation === 'denied-by-acl' ? 'ss-dot--rust'
    : hop.policyViolation === 'blocked' ? 'ss-dot--carbon'
    : hop.tool && hop.tool.startsWith('user-management') ? 'ss-dot--signal'
    : 'ss-dot--kelp';
  const paramsText = hop.params ? JSON.stringify(hop.params, null, fullParams ? 2 : 0) : '';
  // M14 — show a small red "!" chip when Layer B stamped a policy violation
  // on this hop. Clicking through opens the HopDetailSheet which surfaces
  // the full PolicyViolationBadge.
  const policyTag = hop.policyViolation === 'denied-by-acl' ? '!ACL'
                  : hop.policyViolation === 'blocked' ? 'BLOCK' : null;
  return (
    <div className="ss-hop" role="listitem" tabIndex={0}
         aria-label={`Step ${index + 1}: ${hop.tool} completed in ${hop.latencyMs || '?'}ms${policyTag ? ' (policy: ' + policyTag + ')' : ''}`}
         onClick={() => onOpen && onOpen(hop)}
         onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onOpen && onOpen(hop); }}>
      <div className="ss-hop__num">{String(index + 1).padStart(2, '0')}</div>
      <div>
        <div className="ss-hop__name">
          {hop.tool}
          {policyTag && (
            <span
              data-testid="hop-policy-tag"
              data-policy-violation={hop.policyViolation}
              style={{
                marginLeft: 8, padding: '1px 6px', fontSize: 10, fontWeight: 700,
                background: policyTag === '!ACL' ? 'var(--rust)' : 'var(--carbon)',
                color: 'var(--paper)', borderRadius: 2, letterSpacing: '0.06em',
              }}
            >
              {policyTag}
            </span>
          )}
        </div>
        <div className="ss-hop__args">{fullParams ? paramsText : paramsText.slice(0, 60)}</div>
        <div className="ss-hop__status">
          <span className={`ss-dot ${dot}`} />
          {hop.status === 'in-flight' ? 'in-flight' : `${hop.latencyMs || 0}ms`}
        </div>
      </div>
    </div>
  );
}

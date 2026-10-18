import React from 'react';
import { isFixedTurn } from '../../utils/turnModeCapability.mjs';
import SearchEcho from './SearchEcho.jsx';

/**
 * @intentional-vulnerability xss-reflected-search
 * @teaches OWASP-Web:A03
 * @location client/src/pages/secureshop/components/AgentLane/HopDetailSheet.jsx
 * Wave 5A F10 — the `echo_html` field on a product-search.search tool result
 * is rendered here via dangerouslySetInnerHTML. Together with the tool's
 * verbatim echo of the raw query, this is the reflected-XSS end-to-end:
 * chat "search for <script>...</script>", tool builds echo_html, hop sheet
 * renders it as live DOM.
 */
function _pickEchoHtml(result) {
  if (!result || typeof result !== 'object') return null;
  // Tool results arrive in MCP shape { content: [{ type: 'text', text }] }
  // as well as object shape (unit tests bypass the MCP envelope). Support both.
  if (typeof result.echo_html === 'string' && result.echo_html.length) return result.echo_html;
  if (Array.isArray(result.content)) {
    for (const part of result.content) {
      if (!part) continue;
      // Some agents put JSON in the text payload.
      if (part.type === 'text' && typeof part.text === 'string') {
        try {
          const parsed = JSON.parse(part.text);
          if (parsed && typeof parsed.echo_html === 'string') return parsed.echo_html;
        } catch {}
      }
      if (typeof part.echo_html === 'string') return part.echo_html;
    }
  }
  return null;
}

/**
 * M14 — render the Layer B policy_violation annotation as a red banner
 * so students SEE the "policy said no, runtime said yes" moment. Two states:
 *
 *   policyViolation='denied-by-acl' → red banner (LLM06 in action)
 *   policyViolation='blocked'       → gray banner (enforcement mode on)
 */
function PolicyViolationBadge({ violation }) {
  if (!violation) return null;
  const isBlock = violation === 'blocked';
  const label = isBlock
    ? 'Blocked by ACL enforcement'
    : 'Policy violation — ACL denied but runtime allowed (LLM03:2026 excessive agency)';
  const bg = isBlock ? 'color-mix(in srgb, var(--carbon) 8%, transparent)'
                     : 'color-mix(in srgb, var(--rust) 15%, transparent)';
  const border = isBlock ? 'var(--rule)' : 'var(--rust)';
  const color = isBlock ? 'var(--ink)' : 'var(--rust)';
  return (
    <div
      data-testid="policy-violation-badge"
      data-policy-violation={violation}
      style={{
        padding: '10px 14px', marginBottom: 8,
        background: bg, border: `1px solid ${border}`, color,
        fontSize: 13, fontWeight: 600, borderRadius: 4,
        display: 'flex', alignItems: 'center', gap: 8,
      }}
    >
      <span aria-hidden="true">{isBlock ? '\u25A0' : '\u26A0'}</span>
      <span>{label}</span>
    </div>
  );
}

export default function HopDetailSheet({ hop, onClose, searchAssessment }) {
  const open = !!hop;
  const preview = hop && hop.result && hop.result.content && hop.result.content[0] && hop.result.content[0].text;
  const echoHtml = hop ? _pickEchoHtml(hop.result) : null;
  const fixed = isFixedTurn(hop?.modeCapability);
  return (
    <div className={`ss-sheet ${open ? 'ss-sheet--open' : ''}`} role="dialog" aria-hidden={!open}>
      <div className="ss-sheet__head">
        <div>
          <div className="ss-sheet__label">Hop detail</div>
          <div className="ss-mono" style={{ fontSize: 14, marginTop: 4 }}>{hop && hop.tool}</div>
        </div>
        <button className="ss-btn ss-btn--ghost" onClick={onClose}>Close</button>
      </div>
      <div className="ss-sheet__body">
        {hop && hop.policyViolation && <PolicyViolationBadge violation={hop.policyViolation} />}
        <section className="ss-sheet__section">
          <div className="ss-sheet__label">Params</div>
          <pre className="ss-sheet__pre">{hop ? JSON.stringify(hop.params || {}, null, 2) : ''}</pre>
        </section>
        {echoHtml && <SearchEcho echoHtml={echoHtml} fixed={fixed} />}
        {hop?.searchSource && searchAssessment && <section className="ss-sheet__section">
          <div className="ss-sheet__label">Search echo assessment</div>
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={searchAssessment.busy || searchAssessment.blocked}
            onClick={searchAssessment.onCheck}>
            {searchAssessment.saved ? 'Check saved search echo assessment' : 'Check search echo'}
          </button>
          {searchAssessment.blocked && <p role="status">Resolve the saved search assessment before starting another.</p>}
        </section>}
        <section className="ss-sheet__section">
          <div className="ss-sheet__label">Tool result</div>
          {/* Intentional DOM XSS: preview rendered via dangerouslySetInnerHTML per spec §5.3 */}
          {preview && fixed
            ? <pre className="ss-mono" style={{ padding: 12, background: 'var(--carbon)', color: 'var(--paper)', whiteSpace: 'pre-wrap' }}>{preview}</pre>
            : preview
            /* intentional — teaches dom-xss-hop-preview (see spec §5.3 DOM XSS row) */
            ? <div className="ss-mono" style={{ padding: 12, background: 'var(--carbon)', color: 'var(--paper)' }}
                   dangerouslySetInnerHTML={{ __html: preview }} />
            : <pre className="ss-sheet__pre">(no result)</pre>}
        </section>
        <section className="ss-sheet__section">
          <div className="ss-sheet__label">Timing</div>
          <div className="ss-mono">{hop ? `${hop.latencyMs || 0}ms · step ${hop.step || '?'}` : ''}</div>
        </section>
      </div>
    </div>
  );
}

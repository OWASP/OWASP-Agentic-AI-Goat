import React from 'react';
import Hop from './Hop.jsx';
import { isFixedTurn, trustedTurnMode } from '../../utils/turnModeCapability.mjs';

function fmtTime(ms) {
  if (!ms) return '';
  const d = new Date(ms);
  return d.toTimeString().slice(0, 8);
}

const ACTIVITY_LABELS = Object.freeze({
  'catalog.search': ['Searched products', 'product search'],
  'catalog.details': ['Read product details', 'product detail read'],
  'cart.view': ['Viewed cart', 'cart view'],
  'cart.add': ['Prepared cart addition', 'cart addition'],
  'cart.update': ['Prepared cart update', 'cart update'],
  'cart.remove': ['Prepared cart removal', 'cart removal'],
  'orders.list': ['Viewed orders', 'order list read'],
  'orders.details': ['Viewed order details', 'order detail read'],
  'orders.refund_setup': ['Prepared refund review', 'refund review request'],
  'account.addresses': ['Viewed saved addresses', 'address read'],
  'account.address_setup': ['Requested address form', 'address form request'],
  'payment.methods': ['Viewed practice payment methods', 'practice payment method read'],
  'payment.create_method': ['Requested practice payment method', 'practice payment method request'],
  'checkout.prepare': ['Prepared checkout quote', 'checkout quote'],
});
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function savedStockRejection(hop, turn) {
  const mode = trustedTurnMode(turn.modeCapability);
  if (hop.tool !== 'cart.add' || !['ok', 'done'].includes(hop.status) || hop.error
    || turn.status !== 'done' || turn.stopReason !== 'end_turn'
    || mode?.featureId !== 'customer_chat'
    || !exact(hop.result, ['content']) || !Array.isArray(hop.result.content)
    || hop.result.content.length !== 1
    || !exact(hop.result.content[0], ['type', 'text'])
    || hop.result.content[0].type !== 'text'
    || typeof hop.result.content[0].text !== 'string'
    || new TextEncoder().encode(hop.result.content[0].text).byteLength > 16384) return false;
  let observed;
  try { observed = JSON.parse(hop.result.content[0].text); } catch { return false; }
  if (!exact(observed, ['scopeKey', 'version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || !SHA.test(observed.scopeKey) || observed.version !== 1
    || observed.kind !== 'cart.add' || observed.status !== 'rejected'
    || observed.replayed !== false
    || !exact(observed.result, ['code', 'choiceId', 'quantity'])
    || observed.result.code !== 'INSUFFICIENT_STOCK'
    || !Number.isInteger(observed.result.quantity)
    || observed.result.quantity < 1 || observed.result.quantity > 99
    || hop.params?.choiceId !== observed.result.choiceId
    || hop.params?.quantity !== observed.result.quantity) return false;
  return Array.isArray(turn.operations) && turn.operations.some(operation => operation.status === 'completed'
    && operation.operationId === observed.operationId
    && operation.rejection?.code === observed.result.code
    && operation.rejection.choiceId === observed.result.choiceId
    && operation.rejection.quantity === observed.result.quantity);
}

const activityLabel = (hop, turn) => {
  const labels = ACTIVITY_LABELS[hop.tool];
  const fallback = String(hop.tool || 'agent action').replace(/[._]/g, ' ');
  if (hop.policyViolation === 'blocked') return `Blocked ${labels?.[1] || fallback}`;
  if (hop.status === 'error') return `${labels?.[1] || fallback} failed`;
  if (hop.status === 'in-flight') return `Running ${labels?.[1] || fallback}`;
  if (savedStockRejection(hop, turn)) return 'Cart addition rejected';
  return ['ok', 'done'].includes(hop.status) ? (labels?.[0] || fallback)
    : `Agent action: ${labels?.[1] || fallback}`;
};

/**
 * @intentional-vulnerability xss-reflected-search
 * @teaches OWASP-Web:A03
 * @location client/src/pages/secureshop/components/AgentLane/Turn.jsx
 * intentional — the supervisor reply is rendered via dangerouslySetInnerHTML
 * so that echoed search queries and other tool_result content passed through
 * the assistant_message stream are rendered as-is. This is the reflected-XSS
 * sink for `product-search.search` (which echoes the raw query into its
 * response), and is also a general LLM05/output-handling teaching surface.
 * Do NOT sanitize `turn.reply` here — the escape-hatch to safe text rendering
 * would neuter the classroom demo.
 */
export default function Turn({ turn, role = 'customer', onOpenHop, compactHops = false }) {
  const total = turn.finishedAt && turn.startedAt ? ((turn.finishedAt - turn.startedAt) / 1000).toFixed(1) : null;
  const supervisor = `${role.toUpperCase()}-SUPERVISOR`;
  const blocked = turn.hops.filter(hop => hop.policyViolation === 'blocked').length;
  const warnings = turn.hops.filter(hop => hop.policyViolation === 'denied-by-acl').length;
  const activityPreview = turn.hops.slice(-3).map(hop => activityLabel(hop, turn)).join(' → ');
  return (
    <article className="ss-turn" data-testid="agent-turn">
      <div className="ss-turn__you">YOU · {fmtTime(turn.startedAt)}</div>
      <div className="ss-turn__msg">"{turn.user}"</div>

      <div className="ss-turn__supervisor">
        {supervisor}
        {turn.status === 'in-flight' && <><span className="ss-dot ss-dot--amber" /> thinking</>}
        {turn.status === 'done' && <><span className="ss-dot ss-dot--kelp" /> done</>}
        {turn.status === 'error' && <><span className="ss-dot ss-dot--rust" /> error</>}
      </div>

      {compactHops && turn.hops.length > 0
        ? <details className="ss-turn__activity" data-testid="agent-activity">
            <summary>
              <span>Agent activity · {turn.hops.length} {turn.hops.length === 1 ? 'step' : 'steps'}
                {blocked > 0 && ` · ${blocked} blocked`}
                {warnings > 0 && ` · ${warnings} policy ${warnings === 1 ? 'warning' : 'warnings'}`}
              </span>
              <span className="ss-turn__activity-preview">
                {turn.hops.length > 3 ? '… → ' : ''}{activityPreview}
              </span>
            </summary>
            <div className="ss-turn__activity-steps" role="list">
              {turn.hops.map((h, i) => <Hop key={h.id || i} hop={h} index={i}
                onOpen={onOpenHop} fullParams />)}
            </div>
          </details>
        : <div role="list">
            {turn.hops.map((h, i) => <Hop key={h.id || i} hop={h} index={i} onOpen={onOpenHop} />)}
          </div>}

      {turn.reply && (
        <div className="ss-turn__reply">
          <div className="ss-turn__you">{supervisor} · reply</div>
          {turn.modeCapability && <div className="ss-mono" style={{ fontSize: 11, marginTop: 4 }}>
            {turn.modeCapability.featureId} effect policy · {turn.modeCapability.effectiveMode}
          </div>}
          {/* The xss-reflected-search raw sink remains active for vulnerable and legacy turns. */}
          {isFixedTurn(turn.modeCapability)
            ? <div className="ss-turn__reply-html" data-testid="agent-turn-reply">{String(turn.reply)}</div>
            : <div className="ss-turn__reply-html" data-testid="agent-turn-reply"
                dangerouslySetInnerHTML={{ __html: String(turn.reply) }} />}
        </div>
      )}

      {total && <div className="ss-turn__meta">→ {total}s total · {turn.hops.length} hops</div>}
    </article>
  );
}

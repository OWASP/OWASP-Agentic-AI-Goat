const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const raw = (value, bytes) => typeof value === 'string' && !!value.trim()
  && value.isWellFormed() && !value.includes('\0')
  && new TextEncoder().encode(value).byteLength <= bytes;
const timestamp = value => typeof value === 'string'
  && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3,6}Z$/.test(value)
  && Number.isFinite(Date.parse(value));
const invalid = () => { throw new TypeError('Admin ticket unavailable'); };

export function decodeAdminTicketList(value) {
  if (!exact(value, ['version', 'tickets', 'nextCursor']) || value.version !== 1
    || !Array.isArray(value.tickets) || value.tickets.length > 20
    || value.nextCursor !== null && (typeof value.nextCursor !== 'string'
      || !value.nextCursor || new TextEncoder().encode(value.nextCursor).byteLength > 1024)) invalid();
  for (const ticket of value.tickets) {
    if (!exact(ticket, ['ticketId', 'subject', 'status', 'createdAt'])
      || typeof ticket.ticketId !== 'string' || !/^[1-9]\d*$/.test(ticket.ticketId)
      || !raw(ticket.subject, 256) || ticket.status !== 'open'
      || !timestamp(ticket.createdAt)) invalid();
  }
  return value;
}

export function decodeTicketModeCapability(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || value.version !== 1 || value.featureId !== 'support_tickets'
    || value.policyVersion !== 'owned-ticket-render-v1'
    || !['vuln', 'fixed'].includes(value.effectiveMode)
    || !exact(value.scope, ['kind', 'id'])
    || value.scope.kind !== 'launch_feature' || value.scope.id !== 'support_tickets') invalid();
  return value;
}

export function decodeAdminTicketDetail(value) {
  if (!exact(value, ['version', 'ticketId', 'operationId', 'proposalId', 'subject', 'body',
    'status', 'createdAt', 'subjectSha256', 'bodySha256', 'receiptSha256', 'modeCapability'])
    || value.version !== 1 || typeof value.ticketId !== 'string'
    || !/^[1-9]\d*$/.test(value.ticketId) || !UUID.test(value.operationId)
    || !UUID.test(value.proposalId) || value.operationId !== value.proposalId
    || !raw(value.subject, 256) || !raw(value.body, 4096)
    || value.status !== 'open' || !timestamp(value.createdAt)
    || ![value.subjectSha256, value.bodySha256, value.receiptSha256].every(digest => SHA.test(digest))) invalid();
  decodeTicketModeCapability(value.modeCapability);
  return value;
}

export async function ticketTextDigest(value) {
  if (typeof value !== 'string') invalid();
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function verifyAdminTicketDetail(value) {
  const detail = decodeAdminTicketDetail(value);
  if (await ticketTextDigest(detail.subject) !== detail.subjectSha256
    || await ticketTextDigest(detail.body) !== detail.bodySha256) invalid();
  return detail;
}

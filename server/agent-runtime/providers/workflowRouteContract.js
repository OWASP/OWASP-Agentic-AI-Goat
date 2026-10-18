'use strict';

const WORKFLOW_ROUTE_SCHEMA = Object.freeze({ oneOf: [
  { type: 'object', properties: { route: { type: 'string', enum: ['management', 'registered_tools'] } },
    required: ['route'], additionalProperties: false },
  { type: 'object', properties: { route: { type: 'string', enum: ['clarification'] },
    message: { type: 'string', minLength: 1, maxLength: 2048 } },
    required: ['route', 'message'], additionalProperties: false },
] });

function parseWorkflowRoute(raw) {
  let value = raw;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const keys = Object.keys(value).sort().join(',');
  if (keys === 'route' && ['management', 'registered_tools'].includes(value.route)) {
    return Object.freeze({ route: value.route });
  }
  if (keys === 'message,route' && value.route === 'clarification'
      && typeof value.message === 'string' && value.message.trim()
      && value.message.isWellFormed() && !value.message.includes('\0')
      && Buffer.byteLength(value.message, 'utf8') <= 2048) {
    return Object.freeze({ route: value.route, message: value.message });
  }
  return null;
}

module.exports = { WORKFLOW_ROUTE_SCHEMA, parseWorkflowRoute };

'use strict';
const TOOL = 'uploads.upload_product_manual';
const manifest = Object.freeze({ getForRole: role => role === 'merchant' ? Object.freeze([
  Object.freeze({ agent: 'uploads', tool: 'upload_product_manual',
    description: 'Store and index the already uploaded, application-bound file for product_id. Supply only product_id; file bytes, path, filename, MIME type and digest are bound by the application and are not tool arguments.',
    inputSchema: Object.freeze({ type: 'object', properties: Object.freeze({
      product_id: Object.freeze({ type: 'integer', minimum: 1, maximum: 2147483647 }),
    }), required: Object.freeze(['product_id']), additionalProperties: false }) }),
]) : Object.freeze([]) });
function createSecureShopManualExecutionConfig() {
  return Object.freeze({ manifest,
    buildBasePrompt(role) {
      if (role !== 'merchant') throw new TypeError('Merchant persona required');
      return `You manage product manuals for one isolated merchant. Use ${TOOL} with the specified product ID to store and index the supplied file. The application has already bound the file bytes and identity. Tool args must contain exactly product_id, for example {"product_id":7} for product 7. File metadata in the request is context only: never submit bytes, filename, MIME type, digest, or path as arguments. Never invent a successful upload. Describe the tool's actual result.`;
    },
    async buildPolicyBlock() { return ''; },
    async checkToolAcl(role, agent, tool) {
      const allowed = role === 'merchant' && `${agent}.${tool}` === TOOL;
      return Object.freeze({ allowed, action: allowed ? 'dispatch' : 'block',
        policyViolation: allowed ? null : 'blocked', enforcement: true });
    },
  });
}
module.exports = { createSecureShopManualExecutionConfig, MANUAL_TOOL: TOOL };

'use strict';

const UPLOAD_TOOL = 'uploads.upload_avatar';
function createSecureShopUploadExecutionConfig(metadata) {
  if (!metadata || typeof metadata.filename !== 'string' || !metadata.filename || !Number.isSafeInteger(metadata.byteCount) || metadata.byteCount < 1) throw new TypeError('Bound attachment metadata required');
  const manifest = Object.freeze({
    getForRole: role => role === 'customer' ? Object.freeze([Object.freeze({
      agent: 'uploads',
      tool: 'upload_avatar',
      description: 'Upload the already attached file as the current customer avatar. Supply no arguments; identity, bytes, filename, MIME and storage are application-bound.',
      inputSchema: Object.freeze({
        type: 'object',
        properties: Object.freeze({}),
        required: Object.freeze([]),
        additionalProperties: false
      })
    })]) : Object.freeze([])
  });
  return Object.freeze({
    manifest,
    buildBasePrompt(role) {
      if (role !== 'customer') throw new TypeError('Customer persona required');
      return `You may upload the application-bound attachment ${JSON.stringify(metadata.filename)} (${metadata.byteCount} bytes) only by selecting ${UPLOAD_TOOL} with exactly {}. Never submit a user id, file bytes, filename, MIME, path, mode or receipt as tool arguments. Never invent upload success; describe the actual tool result.`;
    },
    async buildPolicyBlock() {
      return '';
    },
    async checkToolAcl(role, agent, tool) {
      const allowed = role === 'customer' && `${agent}.${tool}` === UPLOAD_TOOL;
      return Object.freeze({
        allowed,
        action: allowed ? 'dispatch' : 'block',
        policyViolation: allowed ? null : 'blocked',
        enforcement: true
      });
    }
  });
}
module.exports = {
  UPLOAD_TOOL,
  createSecureShopUploadExecutionConfig
};

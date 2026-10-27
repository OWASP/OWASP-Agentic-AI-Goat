'use strict';
// Explicit historical rows, not current execution permissions. New supported
// tools must not retroactively change the bytes of published v29-and-earlier catalogs.
function registryV29Rows(registry) {
  registry = registryV36Rows(registry);
  const defaults = new Map([
    ['user-management.set_role', { customer: false, merchant: false, admin: true }],
    ['uploads.upload_avatar', { customer: true, merchant: true, admin: true }],
    ['listing.optimize_images', { customer: false, merchant: true, admin: true }],
    ['summarizer.summarize_file', { customer: true, merchant: true, admin: true }],
  ]);
  return registry.filter(row => !['arithmetic.sum', 'merchant.listing_optimize_setup','admin.user_lookup','uploads.preview_legacy_image'].includes(row.toolKey))
    .map(row => defaults.has(row.toolKey) ? {
      toolKey: row.toolKey, workflow: null, supported: false,
      roleApplicability: { customer: false, merchant: false, admin: false },
      defaultAllowed: defaults.get(row.toolKey),
      unavailableReason: 'No supported bound execution workflow',
    } : row);
}
function registryV35Rows(registry) {
  return registryV36Rows(registry).map(row => row.toolKey === 'user-management.set_role' ? {
    toolKey: row.toolKey, workflow: null, supported: false,
    roleApplicability: { customer: false, merchant: false, admin: false },
    defaultAllowed: { customer: false, merchant: false, admin: true },
    unavailableReason: 'No supported bound execution workflow',
  } : row);
}
function registryV36Rows(registry) {
  return registryV37Rows(registry).map(row => row.toolKey === 'mcp-registry.register' ? {
    toolKey: row.toolKey, workflow: null, supported: false,
    roleApplicability: { customer: false, merchant: false, admin: false },
    defaultAllowed: { customer: false, merchant: false, admin: true },
    unavailableReason: 'No supported bound execution workflow',
  } : row);
}
function registryV37Rows(registry) {
  return registryV38Rows(registry).map(row => row.toolKey === 'mcp-registry.describe_tools' ? {
    toolKey: row.toolKey, workflow: null, supported: false,
    roleApplicability: { customer: false, merchant: false, admin: false },
    defaultAllowed: { customer: false, merchant: false, admin: true },
    unavailableReason: 'No supported bound execution workflow',
  } : row);
}
function registryV38Rows(registry) {
  return registry.map(row => row.toolKey === 'mcp-registry.list_servers' ? {
    toolKey: row.toolKey, workflow: null, supported: false,
    roleApplicability: { customer: false, merchant: false, admin: false },
    defaultAllowed: { customer: false, merchant: false, admin: true },
    unavailableReason: 'No supported bound execution workflow',
  } : row);
}
module.exports = { registryV29Rows, registryV35Rows, registryV36Rows, registryV37Rows, registryV38Rows };

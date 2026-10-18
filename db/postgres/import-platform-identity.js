'use strict';

const { withTransaction } = require('../../server/database/postgres');
const { validateIdentityImport, importIdentityInTransaction } = require('../../server/database/postgres/identityImport');
const { preparePlatformImport, applyPlatformSnapshot } = require('./import-platform-snapshot');
const { buildImportBatch, recordImportBatch } = require('./import-batch');
const { applyIdentityAuxiliary } = require('./apply-identity-auxiliary');
const { applyPlatformSolutions } = require('./apply-platform-solutions');
const { applyAdditionalPlatformSolutions } = require('./apply-platform-additional-solutions');
const { normalizeArchiveOwnerBinding, recordArchiveOwnerBinding } = require('./archive-owner-binding');

const INITIAL_CONFIG = [
  { config_key: 'allow_registration', config_value: 'true', config_type: 'boolean', is_public: false },
  { config_key: 'enable_rate_limiting', config_value: 'false', config_type: 'boolean', is_public: false },
  { config_key: 'workshop_signup_random_email_enabled', config_value: 'false', config_type: 'boolean', is_public: false },
];

function prepareCombinedImport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.keys(input).some(key => !['identity', 'platform', 'solutions', 'additionalSolutions', 'identityAuxiliary', 'archiveReview'].includes(key))) {
    throw new Error('Expected explicit identity and platform import inputs');
  }
  const identity = validateIdentityImport(input.identity);
  const platform = preparePlatformImport(input.platform);
  const ownerBinding = normalizeArchiveOwnerBinding({
    archiveDigest: platform.archiveDigest,
    identityMap: input.platform.identityMap,
  });
  const ids = new Set(identity.users.map(user => user.id));
  if (Object.values(input.platform.identityMap).some(id => !ids.has(id))) {
    throw new Error('Platform identity mapping must reference this identity import');
  }
  if (input.additionalSolutions?.identityMap && Object.entries(input.additionalSolutions.identityMap)
    .some(([sourceId, targetId]) => input.platform.identityMap[sourceId] !== targetId || !ids.has(targetId))) {
    throw new Error('Additional solution identity mapping must match the platform import');
  }
  // Preserve an existing administrator; importing must not silently create one.
  const now = Date.now();
  const administrator = identity.users.some(user => user.is_active === 1
    && ['admin', 'super_admin'].includes(user.role) && user.admin_level >= 1
    && (!user.account_locked_until || Date.parse(user.account_locked_until) <= now)
    && identity.permissions.some(permission => permission.admin_id === user.id
      && permission.permission_name === 'user_management' && permission.is_active === 1
      && (!permission.expires_at || Date.parse(permission.expires_at) > now)));
  if (!administrator) throw new Error('Import requires a preserved active administrator with user-management permission');
  return { archiveDigest: platform.archiveDigest, batch: buildImportBatch(input), ownerBinding };
}

/** Native constraint dry run by default. This library does not claim full archive coverage. */
async function importPlatformIdentity(migrationPool, input, { dryRun = true } = {}) {
  if (typeof dryRun !== 'boolean') throw new Error('dryRun must be a boolean');
  if (!migrationPool) throw new Error('A migration database connection is required');
  // Snapshot before awaiting database work so an in-process caller cannot change
  // owners or review decisions between validation and the two apply operations.
  const source = structuredClone(input);
  const prepared = prepareCombinedImport(source);
  return withTransaction(migrationPool, async client => {
    if (dryRun) await client.query('SAVEPOINT combined_import_dry_run');
    const revision = await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
    if (revision.rowCount !== 1 || revision.rows[0].revision !== 0) {
      throw new Error('Combined import requires the initial platform revision');
    }
    await client.query('LOCK TABLE identity.email_verification_tokens,identity.email_agent_progress,identity.sent_emails_log,identity.system_config IN ACCESS EXCLUSIVE MODE');
    for (const table of ['email_verification_tokens', 'email_agent_progress', 'sent_emails_log']) {
      if ((await client.query(`SELECT 1 FROM identity.${table} LIMIT 1`)).rowCount) {
        throw new Error('Combined import requires empty auxiliary identity state');
      }
    }
    const config = (await client.query('SELECT config_key,config_value,config_type,is_public FROM identity.system_config ORDER BY config_key')).rows;
    if (JSON.stringify(config) !== JSON.stringify(INITIAL_CONFIG)) {
      throw new Error('Combined import requires unchanged migration-default system configuration');
    }
    const identity = await importIdentityInTransaction(client, source.identity);
    const identityAuxiliary = source.identityAuxiliary ? await applyIdentityAuxiliary(client, source.identityAuxiliary) : null;
    const platform = await applyPlatformSnapshot(client, source.platform);
    const solutions = source.solutions ? await applyPlatformSolutions(client, source.solutions) : null;
    const additionalSolutions = source.additionalSolutions ? await applyAdditionalPlatformSolutions(client, source.additionalSolutions) : null;
    const administrator = await client.query(`SELECT 1 FROM identity.users u
      JOIN identity.admin_permissions p ON p.admin_id=u.id
      WHERE u.is_active=1 AND u.role IN ('admin','super_admin') AND u.admin_level>=1
        AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
        AND p.permission_name='user_management' AND p.is_active=1
        AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp()) LIMIT 1`);
    if (!administrator.rowCount) throw new Error('Imported administrator became unavailable during import');
    const ownerBinding = await recordArchiveOwnerBinding(client, prepared.ownerBinding);
    await recordImportBatch(client, prepared.batch);
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
    if (dryRun) await client.query('ROLLBACK TO SAVEPOINT combined_import_dry_run');
    return {
      version: prepared.batch.importerVersion, archiveDigest: prepared.archiveDigest,
      planSha256: prepared.batch.planSha256,
      identityMapSha256: ownerBinding.identityMapSha256,
      dryRun, applied: !dryRun, nativeConstraintsChecked: true,
      identity, identityAuxiliary: identityAuxiliary ? { ...identityAuxiliary, applied: !dryRun } : null, platform: { ...platform, applied: !dryRun },
      solutions: solutions ? { ...solutions, applied: !dryRun } : null,
      additionalSolutions: additionalSolutions ? { ...additionalSolutions, applied: !dryRun } : null,
      scope: 'Explicit identity collections and reviewed canonical platform state only; retained tables are not imported.',
    };
  });
}

module.exports = { prepareCombinedImport, importPlatformIdentity };

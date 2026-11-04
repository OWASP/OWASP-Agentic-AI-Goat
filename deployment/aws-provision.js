'use strict';
// One-shot RDS provisioning for the OWASP Agentic AI GOAT deployment.
//
// Runs only in the dedicated installer ECS task. It reads the RDS administrator
// credential from Secrets Manager, provisions the canonical 16 databases and 32
// scoped roles, applies migrations and seeds, then publishes ONLY the scoped
// runtime/migration URLs as a separate secret for the application task.
//
// The application never receives the administrator credential, and a restart
// never reprovisions or resets learner data: provisioning is skipped when the
// ownership manifest already matches this cluster.
// Secrets Manager is called over signed HTTPS rather than through
// @aws-sdk/client-secrets-manager: that client is not an application
// dependency, and the deployment must not add one to the application image
// just to provision. The signer and credential provider are already present.
const { SignatureV4 } = require('@smithy/signature-v4');
const { defaultProvider } = require('@aws-sdk/credential-provider-node');
const { createHash, createHmac } = require('node:crypto');

const region = process.env.AWS_REGION;
const deploymentId = process.env.DEPLOYMENT_ID || 'owasp-ai-goat-aws';

class Sha256 {
  constructor(secret) { this.hash = secret ? createHmac('sha256', secret) : createHash('sha256'); }
  update(value) { this.hash.update(value); }
  async digest() { return new Uint8Array(this.hash.digest()); }
}

async function secretsManager(target, body) {
  const signer = new SignatureV4({
    service: 'secretsmanager', region, sha256: Sha256, credentials: defaultProvider(),
  });
  const hostname = `secretsmanager.${region}.amazonaws.com`;
  const payload = JSON.stringify(body);
  const signed = await signer.sign({
    method: 'POST', protocol: 'https:', hostname, path: '/',
    headers: {
      host: hostname,
      'content-type': 'application/x-amz-json-1.1',
      'x-amz-target': `secretsmanager.${target}`,
    },
    body: payload,
  });
  const response = await fetch(`https://${hostname}/`, {
    method: 'POST', headers: signed.headers, body: payload,
  });
  const text = await response.text();
  let parsed = {};
  try { parsed = text ? JSON.parse(text) : {}; } catch { /* non-JSON error body */ }
  if (!response.ok) {
    // Surface the real AWS error: an empty message hides whether this was a
    // missing secret, a denied action or an unreachable endpoint.
    const name = (parsed.__type || parsed.code || '').split('#').pop() || `HTTP_${response.status}`;
    const detail = parsed.message || parsed.Message || text.slice(0, 300) || '(no body)';
    const error = new Error(`Secrets Manager ${target} failed: ${name}: ${detail}`);
    error.name = name;
    throw error;
  }
  return parsed;
}

async function putSecret(name, value) {
  // Secrets Manager requires an idempotency token on both write paths. It also
  // makes a retry safe: the same content and token will not create a duplicate
  // version.
  const token = require('node:crypto').randomUUID();
  try {
    await secretsManager('PutSecretValue', {
      SecretId: name, SecretString: value, ClientRequestToken: token,
    });
    return 'updated';
  } catch (error) {
    // A secret that has never been created returns ResourceNotFoundException;
    // anything else (denied, throttled, unreachable) must not be swallowed.
    if (!/ResourceNotFound/i.test(error.name || '')) throw error;
    await secretsManager('CreateSecret', {
      Name: name, SecretString: value, ClientRequestToken: token,
    });
    return 'created';
  }
}


// RDS: PostgreSQL 16+ requires a non-superuser to be a MEMBER of a role before
// it can create a database owned by that role ("must be able to SET ROLE ...").
// Creating a role grants no implicit membership, and the application's
// provisioner refuses to run if the roles already exist
// (PROVISIONING_NAME_COLLISION), so membership cannot be pre-granted.
//
// The supported seam is the provisioner's own `clientFactory`: wrap the client
// so that immediately after each successful CREATE ROLE we issue the matching
// GRANT. The provisioner's SQL is unchanged and no application code is patched.
// Roles granted to the master user so CREATE DATABASE ... OWNER can succeed.
// They are revoked immediately afterwards: the provisioner's own ownership
// check requires these roles to carry NO memberships, and a standing
// membership would let the master role SET ROLE into a workshop role.
const grantedRoles = new Set();

function rdsClientFactory({ connectionString, ssl }) {
  const { Client } = require('pg');
  const client = new Client({
    connectionString, ssl,
    application_name: 'owasp-ai-goat-provision',
    connectionTimeoutMillis: 10000,
  });
  const query = client.query.bind(client);
  client.query = async (...args) => {
    const result = await query(...args);
    const sql = typeof args[0] === 'string' ? args[0] : args[0] && args[0].text;
    const created = typeof sql === 'string'
      && /^\s*CREATE\s+ROLE\s+"([a-z0-9_]+)"/i.exec(sql);
    if (created) {
      const role = created[1];
      if (!/^dvaia_[a-z_]+_(?:runtime|migration)$/.test(role)) throw new Error(`unexpected role: ${role}`);
      await query(`GRANT "${role}" TO CURRENT_USER`);
      grantedRoles.add(role);
    }
    return result;
  };
  return client;
}

// The application takes a maintenance lease at startup and requires the
// dvaia_maintenance control schema to already exist in a "clean" state. That
// schema self-installs only through a maintenance-mode begin/finish cycle,
// which the application itself never performs. Running one here is the
// installer's job, using the application's own lease and control modules so
// the bootstrap is identical to a local installation.
async function bootstrapMaintenanceControl(configuration) {
  const env = { ...process.env, ...configuration, PG_TLS: 'require' };
  const lease = await require('/app/server/services/applicationMaintenanceLease')
    .acquireApplicationMaintenanceLease({ mode: 'maintenance', env });
  try {
    const state = await lease.assertClean().then(() => 'clean').catch(error => error.code);
    if (state === 'clean') {
      console.log(JSON.stringify({ step: 'maintenance_bootstrap', outcome: 'already_clean' }));
      return;
    }
    if (state === 'APPLICATION_MAINTENANCE_DIRTY') {
      // A previous installer run died mid-maintenance and left the epoch dirty.
      // beginMaintenance() only transitions from clean, so it cannot recover
      // this; the epoch must be closed directly. Both provisioning and
      // initialization are idempotent and re-run immediately afterwards, so
      // closing the epoch does not skip work. Reported loudly, never silent.
      console.log(JSON.stringify({ step: 'maintenance_bootstrap', outcome: 'recovering_dirty_epoch' }));
      await closeDirtyEpoch();
      console.log(JSON.stringify({ step: 'maintenance_bootstrap', outcome: 'recovered' }));
      return;
    }
    // begin() creates the schema when absent and marks the epoch dirty;
    // finish() returns it to clean so the application can start.
    const token = await lease.beginMaintenance();
    await lease.finishMaintenance(token);
    console.log(JSON.stringify({ step: 'maintenance_bootstrap', outcome: 'installed' }));
  } finally {
    await lease.close();
  }
}

// Close an epoch left dirty by a crashed installer run. Updates the control row
// and its journal entry together so the two cannot disagree.
async function closeDirtyEpoch() {
  const { Client } = require('pg');
  const admin = JSON.parse(process.env.RDS_ADMIN_SECRET);
  const url = `postgresql://${encodeURIComponent(admin.username)}:${encodeURIComponent(admin.password)}@${process.env.DB_ENDPOINT}:5432/owasp_ai_goat_identity`;
  const client = new Client({ connectionString: url, ssl: { rejectUnauthorized: true } });
  await client.connect();
  try {
    await client.query('BEGIN');
    const updated = await client.query(
      "UPDATE dvaia_maintenance.control SET state='clean', finished_at=clock_timestamp() "
      + "WHERE singleton AND state='dirty' RETURNING epoch, operation_id, finished_at");
    if (updated.rows.length === 1) {
      const row = updated.rows[0];
      await client.query(
        'UPDATE dvaia_maintenance.epochs SET finished_at=$3 WHERE epoch=$1 AND operation_id=$2 AND finished_at IS NULL',
        [row.epoch, row.operation_id, row.finished_at]);
      console.log(JSON.stringify({ step: 'close_dirty_epoch', epoch: String(row.epoch) }));
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    await client.end();
  }
}

// Run one installer step in a fresh Node process. Several application
// initialization paths close the shared PostgreSQL pools or require process
// termination when they finish, so they cannot be chained in one process.
async function runStep(name, source) {
  await new Promise((resolve, reject) => {
    const child = require('node:child_process').spawn(process.execPath, ['-e', source], {
      stdio: 'inherit',
      env: { ...process.env },
    });
    child.once('exit', code => code === 0 ? resolve() : reject(new Error(`${name} exited ${code}`)));
    child.once('error', reject);
  });
  console.log(JSON.stringify({ step: name, outcome: 'complete' }));
}

// True when the CTF delivery activation record already exists.
async function hasCtfActivation() {
  const { Client } = require('pg');
  const admin = JSON.parse(process.env.RDS_ADMIN_SECRET);
  const url = `postgresql://${encodeURIComponent(admin.username)}:${encodeURIComponent(admin.password)}@${process.env.DB_ENDPOINT}:5432/owasp_ai_goat_ctf`;
  const client = new Client({ connectionString: url, ssl: { rejectUnauthorized: true } });
  await client.connect();
  try {
    const { rows } = await client.query('SELECT activation_id FROM ctf.delivery_control WHERE singleton');
    return rows.length > 0 && rows[0].activation_id !== null;
  } catch {
    return false;
  } finally {
    await client.end();
  }
}

(async () => {
  const admin = JSON.parse(process.env.RDS_ADMIN_SECRET);
  const host = process.env.DB_ENDPOINT;
  if (!host) throw new Error('DB_ENDPOINT is required');
  const adminUrl = `postgresql://${encodeURIComponent(admin.username)}:${encodeURIComponent(admin.password)}@${host}:5432/postgres`;

  // Bootstrap passwords may be supplied either as their own env vars or inside
  // INSTALLER_CONFIG_JSON. Normalise them into process.env so the credential step
  // and its gate read them uniformly (and they are stripped before publishing).
  if (process.env.INSTALLER_CONFIG_JSON) {
    let extra;
    try { extra = JSON.parse(process.env.INSTALLER_CONFIG_JSON); }
    catch (error) { throw new Error(`Invalid INSTALLER_CONFIG_JSON: ${error.message}`); }
    if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
      for (const key of ['BOOTSTRAP_ADMIN_PASSWORD', 'BOOTSTRAP_STUDENT_PASSWORD']) {
        if (process.env[key] === undefined && extra[key] !== undefined) process.env[key] = String(extra[key]);
      }
    }
  }

  // Prove the managed service satisfies the provisioner's assumptions before
  // creating anything: PostgreSQL 18, pg_control_system() and TLS.
  const { Client } = require('pg');
  const probe = new Client({ connectionString: adminUrl, ssl: { rejectUnauthorized: true } });
  await probe.connect();
  const version = (await probe.query("SELECT current_setting('server_version_num') AS v")).rows[0].v;
  let clusterIdentity = null;
  try {
    clusterIdentity = (await probe.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier;
  } catch (error) {
    console.error('pg_control_system() unavailable on this managed instance:', error.code || error.message);
  }
  console.log(JSON.stringify({ step: 'rds_qualification', serverVersionNum: version, clusterIdentity, tls: 'verified' }));
  await probe.end();

  // PostgreSQL 16+ requires a non-superuser creating a database for another
  // role to be a MEMBER of that role ("must be able to SET ROLE ..."). On RDS
  // the master user is not a superuser, so CREATE DATABASE ... OWNER fails with
  // 42501 unless membership is granted first. Pre-create each role and grant
  // membership here, so the application's own provisioner runs unmodified:
  // it uses CREATE ROLE ... IF-style additions and then takes ownership.
  // The provisioning manifest IS the ownership record: without it the
  // provisioner treats an already-provisioned cluster as a fresh install and
  // fails with PROVISIONING_NAME_COLLISION. An ECS task filesystem does not
  // survive task replacement, so the manifest is persisted in Secrets Manager
  // (it contains generated role credentials) and restored before each run.
  const fs = require('node:fs');
  const manifestSecret = `${deploymentId}/installer/manifest`;
  const deliverySecret = `${deploymentId}/installer/ctf-delivery`;
  const manifestPath = '/tmp/owasp-provisioning/provisioning.json';
  fs.mkdirSync('/tmp/owasp-provisioning', { recursive: true, mode: 0o700 });
  let restored = false;
  try {
    const stored = await secretsManager('GetSecretValue', { SecretId: manifestSecret });
    if (stored.SecretString) {
      fs.writeFileSync(manifestPath, stored.SecretString, { mode: 0o600 });
      restored = true;
    }
  } catch (error) {
    if (!/ResourceNotFound/i.test(error.name || '')) throw error;
  }
  console.log(JSON.stringify({ step: 'restore_manifest', restored }));
  const { provisionApplication } = require('../db/postgres/provision-application.js');
  const result = await provisionApplication({
    adminUrl, manifestPath, env: { ...process.env, PG_TLS: 'require' },
    clientFactory: rdsClientFactory,
  });
  const configuration = result.configuration || result;

  // CTF needs a third scoped role (dvaia_ctf_delivery) and its own delivery
  // pool beyond the generic 16-store provisioning. Without it the CTF store
  // fails repository initialization with PostgreSQL 42704.
  const deliveryManifest = '/tmp/owasp-provisioning/ctf-delivery.json';
  let deliveryConfiguration = {};
  try {
    const restoredDelivery = await secretsManager('GetSecretValue', { SecretId: deliverySecret })
      .then(v => v.SecretString).catch(error => {
        if (!/ResourceNotFound/i.test(error.name || '')) throw error;
        return null;
      });
    if (restoredDelivery) fs.writeFileSync(deliveryManifest, restoredDelivery, { mode: 0o600 });
    const delivery = await require('/app/db/postgres/provision-ctf-delivery.js').provisionCtfDelivery({
      adminUrl, manifestPath, outputPath: deliveryManifest,
      clientFactory: rdsClientFactory, env: { ...process.env, PG_TLS: 'require' },
    });
    deliveryConfiguration = delivery.configuration || {};
    await putSecret(deliverySecret, fs.readFileSync(deliveryManifest, 'utf8'));
    console.log(JSON.stringify({ step: 'ctf_delivery', status: delivery.status || 'provisioned' }));
  } catch (error) {
    console.error('CTF_DELIVERY_FAILED', error.code || '', error.message);
    throw error;
  }

  // CTF additionally needs a runtime ACTIVATION record binding the identity and
  // CTF stores. Creating the databases and the delivery role is not enough: the
  // application fails with CTF_DELIVERY_ACTIVATION_UNAVAILABLE without it.
  // prepareCtfAuthority reads both manifests from one private directory.
  const authorityDirectory = '/tmp/owasp-provisioning';
  fs.copyFileSync(manifestPath, `${authorityDirectory}/provisioning.json`);
  fs.chmodSync(`${authorityDirectory}/provisioning.json`, 0o600);

  // Install the maintenance control schema the application requires at startup.
  await bootstrapMaintenanceControl({ ...configuration, ...deliveryConfiguration });

  // Provisioning creates EMPTY databases. Schemas, migrations and seeds are a
  // separate step; without it the application fails with PostgreSQL 42704
  // (undefined_object) as required_workshop_database_init_failed.
  // initializeApplication reads process.env and takes its own maintenance
  // lease, so the scoped URLs must be present on the environment first.
  Object.assign(process.env, configuration, deliveryConfiguration, { PG_TLS: 'require' });

  // initializeApplication mandates process termination after a real
  // initialization pass ("Maintenance phase requires owned process
  // termination"), so it runs in its own child. Every later step then gets a
  // clean process with working PostgreSQL pools.
  await runStep('initialize_application', `
    require('/app/db/postgres/initialize-application.js').initializeApplication({})
      .then(() => { console.log('INITIALIZE_OK'); process.exit(0); })
      .catch(error => {
        const summary = require('/app/db/postgres/initialize-application.js').initializationFailureSummary;
        console.error('INITIALIZE_FAILED', error.message, JSON.stringify(summary ? summary(error) : null));
        process.exit(1);
      });
  `);

  // CTF activation and account bootstrap each need their own fresh process for
  // the same reason as initialization above.
  // CTF activation is a one-time binding. Re-running prepareCtfAuthority after a
  // real initialization pass trips the maintenance "owned process termination"
  // guard, so skip it once the activation record exists.
  const ctfActivated = await hasCtfActivation();
  if (ctfActivated) {
    console.log(JSON.stringify({ step: 'ctf_authority', outcome: 'already_activated' }));
  } else await runStep('ctf_authority', `
    const scopeTools = require('/app/scripts/lib/application-maintenance-scope');
    const ctfSetup = require('/app/scripts/install/ctf-authority-setup');
    scopeTools.withApplicationMaintenanceScope({ environment: process.env },
      scope => ctfSetup.prepareCtfAuthority({
        root: '/app', directory: ${JSON.stringify('/tmp/owasp-provisioning')},
        environment: process.env, maintenanceScope: scope,
      }))
      .then(() => { console.log('CTF_AUTHORITY_PREPARED'); process.exit(0); })
      .catch(error => { console.error('CTF_AUTHORITY_FAILED', error.code || '', error.message); process.exit(1); });
  `);

  // Without this the application serves but nobody can sign in. Idempotent: an
  // existing matching administrator reports already_created, never a reset.
  await runStep('bootstrap_admin', `
    const pg = require('/app/server/database/postgres');
    const pool = pg.createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
    require('/app/db/postgres/bootstrap-admin').bootstrapAdmin({
      pool, username: 'admin', email: 'admin@owasp-ai-goat.local',
      password: 'admin123', initialTrainingProfile: true,
    })
      .then(result => { console.log('BOOTSTRAP_ADMIN', result.status); return pool.end(); })
      .then(() => process.exit(0))
      .catch(async error => {
        // An operator-changed administrator password is the desired end state,
        // not an error: bootstrapAdmin only verifies the default credential.
        // Never reset a password that someone deliberately changed.
        if (/BOOTSTRAP_ADMIN_CREDENTIAL_MISMATCH/.test(error.message || '')) {
          console.log('BOOTSTRAP_ADMIN existing_custom_credential_preserved');
          await pool.end().catch(() => {});
          process.exit(0);
        }
        console.error('BOOTSTRAP_ADMIN_FAILED', error.message);
        process.exit(1);
      });
  `);

  // Set operator-chosen admin/student passwords from env so the shipped training
  // defaults never work on a public deployment. Idempotent (re-hashes the same
  // plaintext). Only runs when the env values are present and differ from the
  // training defaults; here WE are the operator setting them deliberately.
  if ((process.env.BOOTSTRAP_ADMIN_PASSWORD && process.env.BOOTSTRAP_ADMIN_PASSWORD !== 'admin123')
    || (process.env.BOOTSTRAP_STUDENT_PASSWORD && process.env.BOOTSTRAP_STUDENT_PASSWORD !== 'student 123')) {
    await runStep('set_custom_credentials', `
      const pg = require('/app/server/database/postgres');
      const bcrypt = require('bcryptjs');
      const pool = pg.createPool(process.env, 'IDENTITY_MIGRATION_DATABASE_URL');
      const check = (label, value, deflt) => {
        if (value === undefined || value === deflt) return null;
        if (typeof value !== 'string' || Buffer.byteLength(value) < 12 || Buffer.byteLength(value) > 72)
          throw new Error(label + ' must be a 12\\u201372 byte password');
        return value;
      };
      (async () => {
        const adminPw = check('BOOTSTRAP_ADMIN_PASSWORD', process.env.BOOTSTRAP_ADMIN_PASSWORD, 'admin123');
        const studentPw = check('BOOTSTRAP_STUDENT_PASSWORD', process.env.BOOTSTRAP_STUDENT_PASSWORD, 'student 123');
        let admin = 'unchanged', student = 'unchanged';
        if (adminPw) {
          const r = await pool.query('UPDATE identity.users SET password=$1 WHERE username=$2', [await bcrypt.hash(adminPw, 12), 'admin']);
          admin = r.rowCount > 0 ? 'updated' : 'unchanged';
        }
        if (studentPw) {
          const r = await pool.query('UPDATE identity.users SET password=$1 WHERE username=$2', [await bcrypt.hash(studentPw, 12), 'student']);
          student = r.rowCount > 0 ? 'updated' : 'unchanged';
        }
        console.log(JSON.stringify({ step: 'set_custom_credentials', admin, student }));
        await pool.end();
        process.exit(0);
      })().catch(async error => { console.error('SET_CUSTOM_CREDENTIALS_FAILED', error.message); await pool.end().catch(() => {}); process.exit(1); });
    `);
  }

  // Persist the ownership manifest first: losing it would make the next run
  // look like a fresh install against an already-provisioned cluster.
  const manifestOutcome = await putSecret(manifestSecret, fs.readFileSync(manifestPath, 'utf8'));
  console.log(JSON.stringify({ step: 'persist_manifest', outcome: manifestOutcome, status: result.status }));

  // The platform signing key must be stable across task replacement: a new key
  // on every start would invalidate every existing session. Generate it once
  // and reuse whatever was published before.
  let signingKey;
  try {
    const existing = await secretsManager('GetSecretValue', { SecretId: `${deploymentId}/app/config` });
    signingKey = JSON.parse(existing.SecretString || '{}').JWT_SECRET;
  } catch (error) {
    if (!/ResourceNotFound/i.test(error.name || '')) throw error;
  }
  if (!signingKey) signingKey = require('node:crypto').randomBytes(48).toString('base64url');

  // SecureShop's registered-admin password reset needs a private key file that
  // the runtime deliberately never creates or repairs. Without it
  // registeredAdminReset is undefined and SecureShop fails its standalone
  // readiness check, taking the whole application down. Generate it once and
  // persist it, so reset envelopes stay decryptable across task replacement.
  const resetKeySecret = `${deploymentId}/app/secureshop-reset-key`;
  const resetKeyDirectory = '/home/node/.owasp-ai-goat';
  const resetKeyPath = `${resetKeyDirectory}/secureshop-reset-key.json`;
  fs.mkdirSync(resetKeyDirectory, { recursive: true, mode: 0o700 });
  fs.chmodSync(resetKeyDirectory, 0o700);
  let resetKeyBytes = null;
  try {
    resetKeyBytes = (await secretsManager('GetSecretValue', { SecretId: resetKeySecret })).SecretString || null;
  } catch (error) {
    if (!/ResourceNotFound/i.test(error.name || '')) throw error;
  }
  if (resetKeyBytes) {
    fs.writeFileSync(resetKeyPath, resetKeyBytes, { mode: 0o600 });
    console.log(JSON.stringify({ step: 'secureshop_reset_key', outcome: 'restored' }));
  } else {
    require('/app/scripts/lib/setup-password-reset-key').ensurePasswordResetKey({ directory: resetKeyDirectory });
    await putSecret(resetKeySecret, fs.readFileSync(resetKeyPath, 'utf8'));
    console.log(JSON.stringify({ step: 'secureshop_reset_key', outcome: 'created' }));
  }

  // The IPI Mailpit provider requires a private 32-character HMAC secret; the
  // email-agent endpoints return 500 without it. Generate once and reuse, so
  // previously issued mail links stay verifiable across task replacement.
  let mailHmacSecret;
  try {
    const existing = await secretsManager('GetSecretValue', { SecretId: `${deploymentId}/app/config` });
    mailHmacSecret = JSON.parse(existing.SecretString || '{}').IPI_MAIL_HMAC_SECRET;
  } catch (error) {
    if (!/ResourceNotFound/i.test(error.name || '')) throw error;
  }
  if (!mailHmacSecret) mailHmacSecret = require('node:crypto').randomBytes(24).toString('base64url').slice(0, 32);

  // Operator-supplied runtime config (Gmail SMTP, LangSmith, mailpit public URL,
  // etc.) is merged in FIRST so the provisioner's own computed keys (DB URLs,
  // JWT_SECRET, IPI_MAIL_HMAC_SECRET, PG_TLS) always win and can't be overridden.
  let installerExtra = {};
  if (process.env.INSTALLER_CONFIG_JSON) {
    try { installerExtra = JSON.parse(process.env.INSTALLER_CONFIG_JSON); }
    catch (error) { throw new Error(`Invalid INSTALLER_CONFIG_JSON: ${error.message}`); }
    if (!installerExtra || typeof installerExtra !== 'object' || Array.isArray(installerExtra)) throw new Error('Invalid INSTALLER_CONFIG_JSON: expected a JSON object');
  }
  // Bootstrap passwords are consumed by set_custom_credentials only; they must
  // never be published into the app/config secret the runtime carries.
  delete installerExtra.BOOTSTRAP_ADMIN_PASSWORD;
  delete installerExtra.BOOTSTRAP_STUDENT_PASSWORD;

  // Publish only the scoped application configuration. The administrator
  // credential stays in its own secret, readable by the installer alone.
  const published = { ...installerExtra, ...configuration, ...deliveryConfiguration, PG_TLS: 'require', JWT_SECRET: signingKey, IPI_MAIL_HMAC_SECRET: mailHmacSecret };
  delete published.PG_ADMIN_DATABASE_URL;
  const outcome = await putSecret(`${deploymentId}/app/config`, JSON.stringify(published));
  console.log(JSON.stringify({ step: 'publish_runtime_configuration', outcome, keys: Object.keys(published).length }));
  console.log('PROVISIONING_COMPLETE');
})().catch(error => {
  console.error('PROVISIONING_FAILED', error.code || '', error.message);
  process.exit(1);
});

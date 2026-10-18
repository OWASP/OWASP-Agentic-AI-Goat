const AUTH = '/api/secureshop/auth';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER = /^[A-Za-z0-9_-]{43}$/;
const validRevision = value => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value)
  && (value.length < 19 || value <= '9223372036854775807');
const ROLES = new Set(['customer', 'merchant', 'admin']);
const OBJECTIVE_ID = /^ss_[a-z0-9_]{1,100}$/;
const QUALIFICATIONS = new Set(['native-model', 'native-browser-judge', 'pending']);
const VERDICTS = new Set(['pass', 'fail', 'inconclusive', 'unavailable']);
const DISPOSITIONS = new Set(['not_pass', 'awarded', 'already_complete', 'stale_generation',
  'mode_changed', 'hidden', 'grading_unqualified']);
const SHA256 = /^[a-f0-9]{64}$/;
const shopUserId = value => Number.isSafeInteger(value) && value >= 1 && value <= 2147483647;
const RESET_CONFIRMATION = 'RESET_SHARED_PRACTICE';

const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const future = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && Date.parse(value) > Date.now();

function user(value) {
  if (!value || typeof value !== 'object' || !Number.isSafeInteger(value.id) || value.id < 1
    || !UUID.test(value.principalId || '')
    || typeof value.username !== 'string' || !value.username || !ROLES.has(value.role)) {
    throw new Error('Invalid shop session response');
  }
  return value;
}

function authenticated(value) {
  if (!value || value.authenticated !== true || !future(value.expiresAt)) throw new Error('Invalid shop session response');
  return { user: user(value.user), expiresAt: value.expiresAt };
}

function mode(value) {
  if (!exact(value, ['mode', 'revision']) || !['vuln', 'fixed'].includes(value.mode)
    || !validRevision(value.revision)) {
    throw new Error('Invalid shop mode response');
  }
  return value;
}

function objectiveSetting(value, withLabel = false) {
  if (!exact(value, withLabel
    ? ['objectiveId', 'label', 'enabled', 'qualification', 'revision']
    : ['objectiveId', 'enabled', 'qualification', 'revision'])
    || !OBJECTIVE_ID.test(value.objectiveId)
    || (withLabel && (typeof value.label !== 'string' || !value.label || value.label.length > 4096))
    || typeof value.enabled !== 'boolean'
    || !QUALIFICATIONS.has(value.qualification) || !validRevision(value.revision)) {
    throw new Error('Invalid shop objective response');
  }
  return value;
}

function objectives(value) {
  if (!exact(value, ['objectives']) || !Array.isArray(value.objectives)
    || value.objectives.length > 256) throw new Error('Invalid shop objective response');
  const seen = new Set();
  return value.objectives.map(row => {
    const checked = objectiveSetting(row, true);
    if (seen.has(checked.objectiveId)) throw new Error('Invalid shop objective response');
    seen.add(checked.objectiveId);
    return checked;
  });
}

function assessmentRow(value) {
  if (!exact(value, ['evaluationId', 'objectiveId', 'verdict', 'disposition', 'createdAt',
    'evaluatedAt', 'canRetry', 'childEvaluationId'])
    || !UUID.test(value.evaluationId) || !OBJECTIVE_ID.test(value.objectiveId)
    || !(value.verdict === null || VERDICTS.has(value.verdict))
    || !(value.disposition === null || DISPOSITIONS.has(value.disposition))
    || !Number.isFinite(Date.parse(value.createdAt))
    || !(value.evaluatedAt === null || Number.isFinite(Date.parse(value.evaluatedAt)))
    || typeof value.canRetry !== 'boolean'
    || !(value.childEvaluationId === null || UUID.test(value.childEvaluationId))) {
    throw new Error('Invalid shop assessment response');
  }
  return value;
}

function assessments(value) {
  if (!exact(value, ['judgments']) || !Array.isArray(value.judgments) || value.judgments.length > 20) {
    throw new Error('Invalid shop assessment response');
  }
  const seen = new Set();
  return value.judgments.map(row => {
    const checked = assessmentRow(row);
    if (seen.has(checked.evaluationId)) throw new Error('Invalid shop assessment response');
    seen.add(checked.evaluationId);
    return checked;
  });
}

function progress(value) {
  if (!exact(value, ['principalId', 'shopUserId', 'username', 'role', 'generation', 'objectives',
    'totalObjectives', 'completedObjectives']) || !UUID.test(value.principalId)
    || !shopUserId(value.shopUserId) || typeof value.username !== 'string'
    || !/^[a-z][a-z0-9_]{2,31}$/.test(value.username) || !ROLES.has(value.role)
    || !Number.isSafeInteger(value.generation) || value.generation < 0
    || !Array.isArray(value.objectives) || value.objectives.length > 256
    || !Number.isSafeInteger(value.totalObjectives) || !Number.isSafeInteger(value.completedObjectives)) {
    throw new Error('Invalid shop progress response');
  }
  const objectives = value.objectives;
  if (objectives.some(row => !exact(row, ['objectiveId', 'label', 'completed'])
      || !OBJECTIVE_ID.test(row.objectiveId) || typeof row.label !== 'string' || !row.label
      || new TextEncoder().encode(row.label).length > 4096 || typeof row.completed !== 'boolean')
    || new Set(objectives.map(row => row.objectiveId)).size !== objectives.length
    || value.totalObjectives !== objectives.length
    || value.completedObjectives !== objectives.filter(row => row.completed).length) {
    throw new Error('Invalid shop progress response');
  }
  return { ...value, principalId: value.principalId.toLowerCase() };
}

function progressPage(value, limit) {
  if (!exact(value, ['learners', 'nextCursor']) || !Array.isArray(value.learners)
    || value.learners.length > limit || !(value.nextCursor === null
      || Number.isSafeInteger(value.nextCursor) && value.nextCursor > 0)) {
    throw new Error('Invalid shop progress response');
  }
  const learners = value.learners.map(progress);
  if (new Set(learners.map(row => row.principalId)).size !== learners.length) {
    throw new Error('Invalid shop progress response');
  }
  return { learners, nextCursor: value.nextCursor };
}

function resetReadiness(value, targetId) {
  const person = value?.user;
  if (!exact(value, ['ok', 'user']) || value.ok !== true
    || !exact(person, ['id', 'username', 'email', 'credentialVersion', 'authorityVersion',
      'membershipVersion', 'resetAvailable'])
    || person.id !== targetId || typeof person.username !== 'string' || !person.username
    || typeof person.email !== 'string' || !person.email
    || !validRevision(person.credentialVersion) || !validRevision(person.authorityVersion)
    || !validRevision(person.membershipVersion) || person.resetAvailable !== true) {
    throw new Error('Password reset readiness was not verified');
  }
  return person;
}

function teachingResetReadiness(value, targetId) {
  const person = value?.user;
  if (!exact(value, ['ok', 'user']) || value.ok !== true
    || !exact(person, ['id', 'username', 'email', 'identityKind', 'channel',
      'credentialVersion', 'authorityVersion', 'resetAvailable'])
    || person.id !== targetId || typeof person.username !== 'string' || !person.username
    || typeof person.email !== 'string' || person.identityKind !== 'teaching_persona'
    || person.channel !== 'bound_persona' || !validRevision(person.credentialVersion)
    || !validRevision(person.authorityVersion) || person.resetAvailable !== true) {
    throw new Error('Teaching password reset readiness was not verified');
  }
  return person;
}

function resetReceipt(value, targetId, operationId, kind, teaching = false) {
  const required = kind === 'reset' ? teaching ? ['ok', 'receipt', 'secretAvailable']
    : ['ok', 'receipt', 'secretAvailable', 'replayed']
    : kind === 'reveal' ? ['ok', 'receipt', 'temporaryPassword']
      : ['ok', 'receipt', 'secretAvailable'];
  const receipt = value?.receipt;
  if (!exact(value, required) || value.ok !== true
    || !exact(receipt, ['operationId', 'targetId', 'credentialVersion', 'authorityVersion',
      'receiptSha256', 'expiresAt'])
    || receipt.operationId !== operationId || receipt.targetId !== targetId
    || !validRevision(receipt.credentialVersion) || !validRevision(receipt.authorityVersion)
    || !SHA256.test(receipt.receiptSha256) || !Number.isFinite(Date.parse(receipt.expiresAt))
    || (kind !== 'reveal' && typeof value.secretAvailable !== 'boolean')
    || (kind === 'reset' && !teaching && typeof value.replayed !== 'boolean')
    || (kind === 'reveal' && (typeof value.temporaryPassword !== 'string'
      || !/^[A-Za-z0-9_-]{32,128}$/.test(value.temporaryPassword)))
    || (kind === 'acknowledge' && value.secretAvailable !== false)) {
    throw new Error('Password reset receipt was not verified');
  }
  return value;
}

export function validateShopBootstrap(value) {
  const launch = value?.launch, persona = value?.persona, frameUser = persona?.user;
  if (!exact(value, ['launch', 'bearer', 'persona'])
    || !exact(launch, ['launchId', 'generation', 'credentialVersion', 'expiresAt'])
    || !UUID.test(launch.launchId) || !Number.isSafeInteger(launch.generation) || launch.generation < 1
    || !Number.isSafeInteger(launch.credentialVersion) || launch.credentialVersion < 1
    || !future(launch.expiresAt) || !BEARER.test(value.bearer)
    || !exact(persona, ['token', 'user', 'expiresAt']) || !future(persona.expiresAt)
    || Date.parse(persona.expiresAt) > Date.parse(launch.expiresAt)
    || typeof persona.token !== 'string' || persona.token.length > 8192
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(persona.token)
    || !exact(frameUser, ['id', 'username', 'email', 'role', 'full_name', 'phone'])
    || !Number.isSafeInteger(frameUser.id) || frameUser.id < 1
    || typeof frameUser.username !== 'string' || typeof frameUser.email !== 'string'
    || !ROLES.has(frameUser.role)) throw new Error('Invalid shop bootstrap');
  return value;
}

function scenes(value) {
  if (!exact(value, ['scenes']) || !Array.isArray(value.scenes) || value.scenes.length > 256
    || value.scenes.some(row => !exact(row, ['id', 'label', 'createdAt', 'isDefault'])
      || !UUID.test(row.id) || typeof row.label !== 'string' || !row.label || row.label.length > 200
      || typeof row.createdAt !== 'string' || !Number.isFinite(Date.parse(row.createdAt))
      || typeof row.isDefault !== 'boolean')) throw new Error('Invalid shop practice list');
  return value.scenes;
}

function practiceAdmission(value, operationId) {
  if (!exact(value, ['operationId', 'status', 'sceneId', 'canResume'])
    || value.operationId !== operationId
    || !['unconfirmed', 'pending', 'published', 'retained_unfinished'].includes(value.status)
    || (value.status === 'published' ? !UUID.test(value.sceneId || '') : value.sceneId !== null)
    || typeof value.canResume !== 'boolean'
    || (value.status !== 'pending' && value.canResume)) {
    throw new Error('Shop practice admission was not verified');
  }
  return value;
}

function practiceResetReadiness(value) {
  if (!exact(value, ['available', 'scope', 'launchId', 'generation', 'scene'])
    || typeof value.available !== 'boolean' || value.scope !== 'shared_practice'
    || !UUID.test(value.launchId) || !Number.isSafeInteger(value.generation) || value.generation < 1
    || !exact(value.scene, ['id', 'label']) || !UUID.test(value.scene.id)
    || typeof value.scene.label !== 'string' || !value.scene.label || value.scene.label.length > 200) {
    throw new Error('Shop reset readiness was not verified');
  }
  return { ...value, launchId: value.launchId.toLowerCase(),
    scene: { ...value.scene, id: value.scene.id.toLowerCase() } };
}

function practiceResetReceipt(value) {
  if (!exact(value, ['resetId', 'status', 'cleanupComplete']) || !UUID.test(value.resetId)
    || value.status !== 'committed' || value.cleanupComplete !== true) {
    throw new Error('Shop reset cleanup was not confirmed');
  }
  return { ...value, resetId: value.resetId.toLowerCase() };
}

function practiceResetRecovery(value) {
  if (!exact(value, ['pending'])) throw new Error('Shop reset recovery was not verified');
  if (value.pending === null) return null;
  const pending = value.pending;
  if (!exact(pending, ['resetId', 'launchId', 'fromGeneration', 'toGeneration', 'status', 'scene',
    'sameExecution', 'cleanupComplete'])
    || !UUID.test(pending.resetId) || !UUID.test(pending.launchId)
    || !Number.isSafeInteger(pending.fromGeneration) || pending.fromGeneration < 1
    || !Number.isSafeInteger(pending.toGeneration) || pending.toGeneration !== pending.fromGeneration + 1
    || !['fenced', 'committed', 'aborted'].includes(pending.status)
    || !exact(pending.scene, ['id', 'label']) || !UUID.test(pending.scene.id)
    || typeof pending.scene.label !== 'string' || !pending.scene.label || pending.scene.label.length > 200
    || typeof pending.sameExecution !== 'boolean' || typeof pending.cleanupComplete !== 'boolean') {
    throw new Error('Shop reset recovery was not verified');
  }
  return { ...pending, resetId: pending.resetId.toLowerCase(),
    launchId: pending.launchId.toLowerCase(), scene: { ...pending.scene, id: pending.scene.id.toLowerCase() } };
}

function practiceRecoveryReceipt(value, resetId) {
  if (!exact(value, ['resetId', 'status', 'cleanupComplete', 'activated'])
    || value.resetId !== resetId || !['fenced', 'committed', 'aborted'].includes(value.status)
    || value.cleanupComplete !== true || typeof value.activated !== 'boolean'
    || (value.activated && value.status !== 'committed')) {
    throw new Error('Shop reset recovery cleanup was not confirmed');
  }
  return value;
}

export function createStandaloneShopClient({ fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('Shop fetch required');
  const request = async (path, { method = 'GET', body, launch, personaToken, signal } = {}) => {
    if (personaToken !== undefined && (typeof launch !== 'string' || !BEARER.test(launch)
      || typeof personaToken !== 'string' || personaToken.length > 8192
      || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(personaToken))) {
      throw new TypeError('Current private shop authority required');
    }
    const response = await fetchImpl(path, { method, credentials: launch ? 'omit' : 'include', redirect: 'error', signal,
      headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(launch ? { 'X-DVAIA-SecureShop-Launch': launch } : {}),
        ...(personaToken ? { Authorization: `Bearer ${personaToken}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const mime = (response.headers?.get?.('content-type') || '').split(';')[0].trim().toLowerCase();
    if (mime !== 'application/json') throw new Error('Shop service unavailable');
    const data = await response.json();
    if (!response.ok) {
      const error = new Error(data?.error || 'Shop service unavailable');
      error.status = response.status; error.code = data?.code;
      if (['SHOP_PRACTICE_CAPACITY', 'SHOP_PRACTICE_CONFLICT'].includes(data?.code)
        && UUID.test(data?.operationId || '')) error.operationId = data.operationId.toLowerCase();
      throw error;
    }
    return data;
  };
  return Object.freeze({
    async getBoundAdminScope(launch, personaToken, signal) {
      const value = await request('/api/secureshop/admin/users?page=1&pageSize=1',
        { launch, personaToken, signal });
      if (value?.ok !== true || typeof value?.administration?.scopeKey !== 'string'
        || value.administration.scopeKey.length > 512) throw new Error('Current administrator scope unavailable');
      return value.administration.scopeKey;
    },
    async getBoundPasswordResetSetup(launch, personaToken, sessionId, requestId, signal) {
      if (!UUID.test(sessionId || '') || !UUID.test(requestId || '')) throw new TypeError('Saved assistant turn required');
      return request(`/api/secureshop/agents/admin/assistant/operations/${sessionId.toLowerCase()}/${requestId.toLowerCase()}`,
        { launch, personaToken, signal });
    },
    async getTeachingResetReadiness(launch, personaToken, targetId, signal) {
      if (!shopUserId(targetId)) throw new TypeError('Shop user required');
      return teachingResetReadiness(await request(`/api/secureshop/admin/users/${targetId}/reset-readiness`,
        { launch, personaToken, signal }), targetId);
    },
    async resetTeachingPassword(launch, personaToken, targetId, operation, signal) {
      if (!shopUserId(targetId) || !UUID.test(operation?.operationId || '')
        || !validRevision(operation?.expectedCredentialVersion)
        || !validRevision(operation?.expectedAuthorityVersion)) throw new TypeError('Current teaching reset required');
      const operationId = operation.operationId.toLowerCase();
      return resetReceipt(await request(`/api/secureshop/admin/users/${targetId}/reset-password`,
        { method: 'POST', launch, personaToken, body: { operationId,
          expectedCredentialVersion: operation.expectedCredentialVersion,
          expectedAuthorityVersion: operation.expectedAuthorityVersion }, signal }),
      targetId, operationId, 'reset', true);
    },
    async getTeachingResetStatus(launch, personaToken, targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Teaching reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`/api/secureshop/admin/users/${targetId}/password-resets/${canonicalId}`,
        { launch, personaToken, signal }), targetId, canonicalId, 'status', true);
    },
    async revealTeachingReset(launch, personaToken, targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Teaching reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`/api/secureshop/admin/users/${targetId}/password-resets/${canonicalId}/reveal`,
        { method: 'POST', body: {}, launch, personaToken, signal }), targetId, canonicalId, 'reveal', true);
    },
    async acknowledgeTeachingReset(launch, personaToken, targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Teaching reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`/api/secureshop/admin/users/${targetId}/password-resets/${canonicalId}/acknowledge`,
        { method: 'POST', body: {}, launch, personaToken, signal }), targetId, canonicalId, 'acknowledge', true);
    },
    async session(signal) {
      const value = await request(`${AUTH}/session`, { signal });
      if (value?.authenticated === false && value.user === null) return null;
      if (value?.authenticated !== true) throw new Error('Invalid shop session response');
      return { user: user(value.user), expiresAt: null };
    },
    async login(username, password) {
      return authenticated(await request(`${AUTH}/login`, { method: 'POST', body: { username, password } }));
    },
    async register({ username, email, password, role }) {
      return authenticated(await request(`${AUTH}/register`, { method: 'POST',
        body: { username, email, password, role } }));
    },
    async renew(signal) { return authenticated(await request(`${AUTH}/renew`, { method: 'POST', body: {}, signal })); },
    async logout() {
      const value = await request(`${AUTH}/logout`, { method: 'POST', body: {} });
      if (value?.authenticated !== false) throw new Error('Shop sign-out was not confirmed');
    },
    async password(currentPassword, newPassword) {
      const value = await request(`${AUTH}/password`, { method: 'POST',
        body: { currentPassword, newPassword } });
      if (value?.authenticated !== false || value.passwordChanged !== true) {
        throw new Error('Password change was not confirmed');
      }
    },
    async getMode(signal) { return mode(await request(`${AUTH}/mode`, { signal })); },
    async getPracticeResetReadiness(signal) {
      return practiceResetReadiness(await request(`${AUTH}/reset-readiness`, { signal }));
    },
    async getPracticeResetRecovery(signal) {
      return practiceResetRecovery(await request(`${AUTH}/reset-recovery`, { signal }));
    },
    async resumePracticeReset(resetId, signal) {
      if (!UUID.test(resetId || '')) throw new TypeError('Shop reset reference required');
      const canonicalId = resetId.toLowerCase();
      return practiceRecoveryReceipt(await request(`${AUTH}/reset-recovery`, { method: 'POST',
        body: { resetId: canonicalId }, signal }), canonicalId);
    },
    async resetPractice(input, signal) {
      if (!exact(input, ['launchId', 'expectedGeneration', 'idempotencyKey', 'sceneId', 'confirmation'])
        || !UUID.test(input.launchId) || !Number.isSafeInteger(input.expectedGeneration)
        || input.expectedGeneration < 1 || !UUID.test(input.idempotencyKey)
        || !UUID.test(input.sceneId) || input.confirmation !== RESET_CONFIRMATION) {
        throw new TypeError('Current shared practice reset required');
      }
      const body = { ...input, launchId: input.launchId.toLowerCase(),
        idempotencyKey: input.idempotencyKey.toLowerCase(), sceneId: input.sceneId.toLowerCase() };
      return practiceResetReceipt(await request(`${AUTH}/reset`, { method: 'POST', body, signal }));
    },
    async setMode(nextMode, expectedRevision, signal) {
      if (!['vuln', 'fixed'].includes(nextMode) || typeof expectedRevision !== 'string'
        || !validRevision(expectedRevision)) {
        throw new TypeError('Current shop mode required');
      }
      return mode(await request(`${AUTH}/mode`, { method: 'POST',
        body: { mode: nextMode, expectedRevision }, signal }));
    },
    async getAssessmentObjectives(signal) {
      return objectives(await request(`${AUTH}/assessment-objectives`, { signal }));
    },
    async setAssessmentObjective(objectiveId, enabled, expectedRevision, signal) {
      if (!OBJECTIVE_ID.test(objectiveId || '') || typeof enabled !== 'boolean'
        || !validRevision(expectedRevision)) throw new TypeError('Current shop objective required');
      const result = objectiveSetting(await request(`${AUTH}/assessment-objectives`, { method: 'POST',
        body: { objectiveId, enabled, expectedRevision }, signal }));
      if (result.objectiveId !== objectiveId || result.enabled !== enabled
        || (result.qualification === 'pending' && enabled)) {
        throw new Error('Shop objective change was not confirmed');
      }
      return result;
    },
    async getAssessments(signal) {
      return assessments(await request(`${AUTH}/assessments`, { signal }));
    },
    async getProgress(signal) {
      return progress(await request(`${AUTH}/progress`, { signal }));
    },
    async getAdminProgressLearners({ limit = 25, cursor = null } = {}, signal) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50
        || !(cursor === null || Number.isSafeInteger(cursor) && cursor >= 0)) {
        throw new TypeError('Shop progress page required');
      }
      const query = `?limit=${limit}${cursor === null ? '' : `&cursor=${cursor}`}`;
      return progressPage(await request(`${AUTH}/admin/progress/learners${query}`, { signal }), limit);
    },
    async getAdminProgress(principalId, signal) {
      if (typeof principalId !== 'string' || !UUID.test(principalId)) {
        throw new TypeError('Shop learner required');
      }
      const id = principalId.toLowerCase();
      const value = progress(await request(`${AUTH}/admin/progress/${id}`, { signal }));
      if (value.principalId !== id) throw new Error('Invalid shop progress response');
      return value;
    },
    async retryAssessment(evaluationId, signal) {
      if (!UUID.test(evaluationId || '')) throw new TypeError('Evaluation identifier required');
      const canonicalId = evaluationId.toLowerCase();
      const value = await request(`${AUTH}/assessments/retry`, { method: 'POST',
        body: { evaluationId: canonicalId }, signal });
      if (!exact(value, ['evaluationId', 'childEvaluationId', 'verdict', 'disposition', 'completed', 'replayed'])
        || value.evaluationId !== canonicalId || !UUID.test(value.childEvaluationId)
        || !VERDICTS.has(value.verdict) || !DISPOSITIONS.has(value.disposition)
        || typeof value.completed !== 'boolean' || typeof value.replayed !== 'boolean'
        || value.completed !== ['awarded', 'already_complete'].includes(value.disposition)) {
        throw new Error('Shop assessment retry was not confirmed');
      }
      return value;
    },
    async getResetReadiness(targetId, signal) {
      if (!shopUserId(targetId)) throw new TypeError('Shop user required');
      return resetReadiness(await request(`${AUTH}/admin/users/${targetId}/reset-readiness`, { signal }), targetId);
    },
    async resetUserPassword(targetId, operation, signal) {
      if (!shopUserId(targetId) || !UUID.test(operation?.operationId || '')
        || !validRevision(operation?.expectedCredentialVersion)
        || !validRevision(operation?.expectedAuthorityVersion)
        || !validRevision(operation?.expectedMembershipVersion)) throw new TypeError('Current password reset required');
      const operationId = operation.operationId.toLowerCase();
      return resetReceipt(await request(`${AUTH}/admin/users/${targetId}/reset-password`, {
        method: 'POST', body: { operationId, expectedCredentialVersion: operation.expectedCredentialVersion,
          expectedAuthorityVersion: operation.expectedAuthorityVersion,
          expectedMembershipVersion: operation.expectedMembershipVersion }, signal,
      }), targetId, operationId, 'reset');
    },
    async getPasswordResetStatus(targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Password reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`${AUTH}/admin/users/${targetId}/password-resets/${canonicalId}`, { signal }),
        targetId, canonicalId, 'status');
    },
    async revealPasswordReset(targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Password reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`${AUTH}/admin/users/${targetId}/password-resets/${canonicalId}/reveal`, {
        method: 'POST', body: {}, signal,
      }), targetId, canonicalId, 'reveal');
    },
    async acknowledgePasswordReset(targetId, operationId, signal) {
      if (!shopUserId(targetId) || !UUID.test(operationId || '')) throw new TypeError('Password reset reference required');
      const canonicalId = operationId.toLowerCase();
      return resetReceipt(await request(`${AUTH}/admin/users/${targetId}/password-resets/${canonicalId}/acknowledge`, {
        method: 'POST', body: {}, signal,
      }), targetId, canonicalId, 'acknowledge');
    },
    async importCart(requestId, items) {
      if (!UUID.test(requestId || '') || !Array.isArray(items) || items.length < 1 || items.length > 50
        || items.some(item => !item || !Number.isSafeInteger(item.productId)
          || item.productId < 1 || item.productId > 2147483647
          || !Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 99)) {
        throw new TypeError('Saved cart import required');
      }
      const canonicalId = requestId.toLowerCase();
      const value = await request(`${AUTH}/cart-import`, { method: 'POST', body: { requestId: canonicalId, items } });
      if (value?.requestId !== canonicalId || typeof value.imported !== 'boolean'
        || typeof value.replayed !== 'boolean') throw new Error('Cart import response was not confirmed');
      if (value.imported) {
        const requested = new Map(items.map(item => [item.productId, item.quantity]));
        if (!Array.isArray(value.items) || value.items.length !== requested.size
          || !Number.isFinite(value.subtotal) || value.subtotal < 0
          || value.items.some(item => !item || requested.get(item.productId) !== item.quantity
            || !Number.isFinite(item.price) || item.price < 0 || typeof item.name !== 'string')) {
          throw new Error('Cart import response was not confirmed');
        }
      } else if (!Array.isArray(value.issues) || !value.issues.length
        || value.issues.some(issue => !issue || !items.some(item => item.productId === issue.productId)
          || !['UNAVAILABLE', 'INSUFFICIENT_STOCK', 'CART_QUANTITY_LIMIT'].includes(issue.code))) {
        throw new Error('Cart import response was not confirmed');
      }
      return value;
    },
    async bootstrap(signal) {
      return validateShopBootstrap(await request(`${AUTH}/bootstrap`, { method: 'POST', body: {}, signal }));
    },
    async createPractice(operationId, signal) {
      if (!UUID.test(operationId || '')) throw new TypeError('Shop practice operation required');
      const id = operationId.toLowerCase();
      return practiceAdmission(await request(`${AUTH}/practices`, { method: 'POST',
        body: { operationId: id }, signal }), id);
    },
    async getPractice(operationId, signal) {
      if (!UUID.test(operationId || '')) throw new TypeError('Shop practice operation required');
      const id = operationId.toLowerCase();
      return practiceAdmission(await request(`${AUTH}/practices/${id}`, { signal }), id);
    },
    async scenes(launch, signal) {
      if (!BEARER.test(launch || '')) throw new TypeError('Shop launch required');
      return scenes(await request('/api/secureshop/v2/scenes', { launch, signal }));
    },
    async selectScene(launch, sceneId, signal) {
      if (!BEARER.test(launch || '') || !UUID.test(sceneId || '')) throw new TypeError('Shop practice required');
      const value = await request('/api/secureshop/v2/scenes/select', { method: 'POST',
        body: { sceneId }, launch, signal });
      if (!value || value.id !== sceneId || value.isDefault !== true) throw new Error('Shop practice selection was not confirmed');
      return value;
    },
  });
}

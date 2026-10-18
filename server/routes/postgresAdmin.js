'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { projectAdminWorkshopView, readAdminWorkshopActivity } = require('../services/adminWorkshopView');
const { projectWorkshopChallenges } = require('../services/workshopChallengeProjection');
const { isWorkshopSurfaceEligible } = require('../config/workshopCatalog');
const { createPostgresAdminRepository } = require('../database/postgres/adminRepository');
const identityValidation = require('../database/postgres/identityValidation');
const { createAdminProgressAnalyticsRepository } = require('../database/postgres/adminProgressAnalyticsRepository');
const { CHALLENGE_IDS: XSS_LEGACY_IDS, createXssLegacyAdminRepository } = require('../database/postgres/xssLegacyAdminRepository');

const solutionRoutes = new Map([
  ['pi-workshop', 'direct_prompt_injection'],
  ['xss-workshop/objective-solutions', 'xss_workshop'],
  ['csrf-workshop/objective-solutions', 'csrf_workshop'],
  ['finflow-workshop', 'sensitive_info_disclosure'],
  ['supply-chain-workshop', 'supply_chain_rce'],
  ['ea-workshop', 'excessive_agency'],
  ['ipi-workshop', 'indirect_prompt_injection'],
  ['mcp-workshop', 'mcp_workshop'],
  ['sql-injection-workshop', 'sql_injection_workshop'],
  ['nosql-injection-workshop', 'nosql_injection_workshop'],
]);

function bool(value) {
  if (typeof value !== 'boolean') throw Object.assign(new Error('enabled must be a boolean'), { code: 'BAD_REQUEST' });
  return value;
}

function failure(res, error, fallback = 'Administrative operation failed') {
  if (error?.statusCode) return res.status(error.statusCode).json({ error: error.message, code: error.code });
  if (error?.code === 'NOT_FOUND') return res.status(404).json({ error: error.message });
  if (error?.code === 'BAD_REQUEST' || error instanceof TypeError) return res.status(400).json({ error: error.message });
  if (error?.code === '23505') return res.status(409).json({ error: 'Username or email already exists' });
  console.error('[PostgresAdmin]', error);
  return res.status(500).json({ error: fallback });
}

function createPostgresAdminRouter({ adapter, stores, auth, repository, resetService, operational,
  xssLegacyRepository, deletionService, analytics } = {}) {
  adapter ||= require('../services/postgresIdentityAdapter').getPostgresIdentityAdapter();
  stores ||= require('../services/postgresPlatformStores').getPostgresPlatformStores();
  auth ||= require('../middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
  repository ||= createPostgresAdminRepository(stores.pool || adapter.pool);
  xssLegacyRepository ||= createXssLegacyAdminRepository(stores.pool || adapter.pool);
  resetService ||= require('../services/postgresWorkshopResetService').getPostgresWorkshopResetService();
  operational ||= require('./adminOperationalHandlers').createAdminOperationalHandlers();
  deletionService ||= { deleteStudent: input => require('../services/studentDeletionApplication')
    .getStudentDeletionApplication().deleteStudent(input) };
  const { authenticateToken, requireAdminLevel, requirePermission, logActivity } = auth;
  const router = express.Router();
  const config = stores.config;
  const progress = stores.progress;

  router.use(authenticateToken);

  router.get('/students', requirePermission('manage_progress'), async (_req, res) => {
    try {
      const students = await repository.listStudents();
      const projections = await progress.getVisibleUsersProgress(students.map(student => student.id));
      res.json({ success: true, students: students.map(student => {
        const challenges = projectWorkshopChallenges(projections.get(student.id) || []);
        const completed = challenges.filter(item => item.status === 'completed').length;
        return { ...student, completed_challenges: completed, completedChallenges: completed,
          total_challenges: challenges.length, totalChallenges: challenges.length,
          totalObjectives: challenges.reduce((sum, item) => sum + item.objectiveCount, 0),
          completedObjectives: challenges.reduce((sum, item) => sum + item.completedObjectiveCount, 0),
          totalTime: challenges.reduce((sum, item) => sum + item.timeSpentSeconds, 0) };
      }) });
    } catch (error) { failure(res, error, 'Failed to fetch students'); }
  });

  router.get('/users/locked', requireAdminLevel(1), logActivity('admin_view_locked_users'), async (_req, res) => {
    try {
      const lockedUsers = (await repository.listLockedUsers()).map(user => {
        const remainingMinutes = user.account_locked_until
          ? Math.max(0, Math.ceil((new Date(user.account_locked_until).getTime() - Date.now()) / 60000)) : 0;
        return { ...user, isCurrentlyLocked: remainingMinutes > 0, remainingMinutes,
          lockoutReason: remainingMinutes ? `Account locked for ${remainingMinutes} more minutes`
            : `${user.login_attempts} failed login attempts` };
      });
      res.json({ success: true, lockedUsers, count: lockedUsers.length });
    } catch (error) { failure(res, error, 'Failed to fetch locked users'); }
  });

  router.get('/users', requirePermission('user_management'), logActivity('admin_users_list'), async (req, res) => {
    try { res.json({ success: true, ...(await repository.listUsers(req.query)) }); }
    catch (error) { failure(res, error, 'Failed to fetch users'); }
  });

  router.get('/users/:userId', requirePermission('user_management'), logActivity('admin_user_details'), async (req, res) => {
    try {
      const detail = await repository.getUser(req.params.userId);
      if (!detail) return res.status(404).json({ error: 'User not found' });
      const userProgress = projectWorkshopChallenges(await progress.getVisibleUserProgress(detail.user.id));
      res.json({ success: true, ...detail, progress: userProgress });
    } catch (error) { failure(res, error, 'Failed to fetch user details'); }
  });

  const updateUser = async (req, res) => {
    try {
      const user = await repository.updateUser(req.params.userId, req.body,
        { id: req.user.id, sessionId: req.identitySession?.id, level: req.user.admin_level });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({ success: true, message: 'User updated successfully', changes: 1, user });
    } catch (error) { failure(res, error, 'Failed to update user'); }
  };
  const updateStudent = async (req, res) => {
    try {
      const user = await repository.updateStudent(req.params.userId, req.body,
        { id: req.user.id, sessionId: req.identitySession?.id, level: req.user.admin_level });
      if (!user) return res.status(404).json({ error: 'Student not found' });
      res.json({ success: true, message: 'Student updated successfully', changes: 1, user });
    } catch (error) { failure(res, error, 'Failed to update student'); }
  };
  router.put('/users/:userId', requirePermission('user_management'), logActivity('admin_user_update'), updateUser);
  router.put('/students/:userId', requireAdminLevel(1), requirePermission('user_management'),
    logActivity('admin_student_update'), updateStudent);

  for (const [action, locked] of [['lock', true], ['unlock', false]]) {
    router.post(`/users/:userId/${action}`, requireAdminLevel(1), requirePermission('user_management'),
      logActivity(`admin_user_${action}`), async (req, res) => {
      try {
        const user = await repository.setUserLock({ userId: req.params.userId, locked,
          actorId: req.user.id, sessionId: req.identitySession?.id,
          actorUsername: req.user.username, ipAddress: req.ip });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true, message: `Account ${locked ? 'locked' : 'unlocked'} successfully`, changes: 1 });
      } catch (error) { failure(res, error, `Failed to ${action} account`); }
    });
  }

  router.post('/students', requireAdminLevel(1), requirePermission('user_management'), logActivity('admin_student_create'), async (req, res) => {
    try {
      if (!req.body.password) throw Object.assign(new Error('Password is required'), { code: 'BAD_REQUEST' });
      if ((req.body.role !== undefined && req.body.role !== 'student') ||
          (req.body.adminLevel !== undefined && req.body.adminLevel !== 0)) {
        return res.status(400).json({ error: 'Student creation cannot assign administrator privileges' });
      }
      const user = await repository.createUser({ username: req.body.username, email: req.body.email,
        fullName: Object.hasOwn(req.body, 'fullName') ? req.body.fullName : req.body.full_name, role: 'student', adminLevel: 0,
        passwordHash: await bcrypt.hash(req.body.password, 12) });
      res.status(201).json({ success: true, message: 'Student created successfully', user });
    } catch (error) { failure(res, error, 'Failed to create student'); }
  });

  router.post('/administrators', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_administrator_create'), async (req, res) => {
      try {
        const body = req.body || {};
        if (body.role !== undefined && body.role !== 'admin') {
          throw Object.assign(new Error('Administrator role must be admin'), { code: 'BAD_REQUEST' });
        }
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const email = typeof body.email === 'string' ? body.email.trim() : '';
        const fullNameInput = Object.hasOwn(body, 'fullName') ? body.fullName : body.full_name;
        const fullName = fullNameInput == null || fullNameInput === '' ? null : fullNameInput;
        if (username.length < 3 || username.length > 50 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            email.length > 320 || (fullName !== null && (typeof fullName !== 'string' ||
            !fullName.trim() || fullName.length > 200)) || typeof body.password !== 'string' ||
            body.password.length < 8 || Buffer.byteLength(body.password, 'utf8') > 72 ||
            ![1, 2].includes(body.adminLevel) || !Array.isArray(body.permissions) ||
            !body.permissions.length || new Set(body.permissions).size !== body.permissions.length ||
            body.permissions.some(permission => !identityValidation.PERMISSIONS.has(permission) || permission === 'database_access')) {
          throw Object.assign(new Error('Invalid administrator account details or password'), { code: 'BAD_REQUEST' });
        }
        const user = await repository.createAdministrator({ username, email,
          fullName: fullName?.trim() || null, passwordHash: await bcrypt.hash(body.password, 12),
          adminLevel: body.adminLevel, permissions: body.permissions,
          actorId: req.user.id, sessionId: req.identitySession?.id, ipAddress: req.ip });
        res.status(201).json({ success: true, message: 'Administrator created successfully', user,
          permissions: body.permissions });
      } catch (error) { failure(res, error, 'Failed to create administrator'); }
    });

  router.put('/administrators/:userId', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_administrator_update'), async (req, res) => {
      try {
        const result = await repository.updateAdministrator({ userId: req.params.userId, input: req.body,
          actorId: req.user.id, sessionId: req.identitySession?.id, ipAddress: req.ip });
        if (!result) return res.status(404).json({ error: 'Administrator not found' });
        res.json({ success: true, message: 'Administrator updated successfully', ...result });
      } catch (error) { failure(res, error, 'Failed to update administrator'); }
    });
  router.delete('/administrators/:userId', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_administrator_deactivate'), async (req, res) => {
      try {
        const result = await repository.deactivateAdministrator({ userId: req.params.userId,
          actorId: req.user.id, sessionId: req.identitySession?.id, ipAddress: req.ip });
        if (!result) return res.status(404).json({ error: 'Administrator not found' });
        res.json({ success: true, message: 'Administrator deactivated successfully', ...result });
      } catch (error) { failure(res, error, 'Failed to deactivate administrator'); }
    });

  router.delete('/students/:studentId', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_student_delete'), async (req, res) => {
    try {
      if (Number(req.params.studentId) === Number(req.user.id)) return res.status(400).json({ error: 'Cannot delete your own account' });
      const result = await deletionService.deleteStudent({ requesterId: req.user.id,
        subjectId: req.params.studentId });
      if (result?.completed !== true) throw Object.assign(new Error('Student deletion is pending cleanup'), {
        code: 'DELETION_UNAVAILABLE', statusCode: 503,
      });
      res.json({ success: true, message: 'Student deleted successfully', jobId: result.jobId });
    } catch (error) { failure(res, error, 'Failed to delete student'); }
  });

  async function rotatePassword(req, res, userId, requireCurrent, studentOnly = false) {
    try {
      userId = Number(userId);
      const credential = studentOnly ? null : await adapter.repository.findCredentialById(userId);
      if (studentOnly && !await repository.getMutableStudent(userId)) return res.status(404).json({ error: 'Student not found' });
      if (!studentOnly && !credential) return res.status(404).json({ error: 'User not found' });
      if (requireCurrent && !(await bcrypt.compare(req.body.currentPassword || '', credential.password))) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      const password = req.body.newPassword || req.body.password;
      if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
      const passwordHash = await bcrypt.hash(password, 12);
      const result = studentOnly
        ? await adapter.repository.rotateStudentPasswordAndRevoke(userId, passwordHash)
        : await adapter.repository.rotatePasswordAndRevoke(userId, credential.password, passwordHash);
      if (!result) return res.status(404).json({ error: studentOnly ? 'Student not found' : 'User not found' });
      res.json({ success: true, message: 'Password changed successfully', sessionsRevoked: result.sessionsRevoked });
    } catch (error) { failure(res, error, 'Failed to change password'); }
  }
  router.post('/account/change-password', requireAdminLevel(1), logActivity('admin_password_change'),
    (req, res) => rotatePassword(req, res, req.user.id, true));
  router.post('/students/:studentId/change-password', requireAdminLevel(1), requirePermission('user_management'),
    logActivity('admin_student_password_change'),
    (req, res) => rotatePassword(req, res, req.params.studentId, false, true));

  router.get('/challenges', requireAdminLevel(1), logActivity('admin_challenges_list'), async (_req, res) => {
    try {
      const configurations = (await repository.listExercisesWithStats({ includeStandaloneApps: true })).map(row => ({ ...row,
        id: row.workshop_key, workshopKey: row.workshop_key, key: row.challenge_key, name: row.challenge_name,
        description: row.challenge_description, enabled: row.is_visible,
        showSolutions: row.show_solutions, showHints: row.show_hints,
        completions: row.students_completed || 0 }));
      res.json({ success: true,
        challenges: configurations.filter(row => isWorkshopSurfaceEligible(row.workshopKey)),
        applications: configurations.filter(row => !isWorkshopSurfaceEligible(row.workshopKey)) });
    } catch (error) { failure(res, error, 'Failed to fetch challenges'); }
  });

  async function exerciseToggle(req, res) {
    try {
      const challengeKey = req.body.challengeKey || req.params.challengeKey;
      const enabled = req.body.enabled ?? req.body.isVisible;
      const result = enabled === undefined
        ? await config.toggleExerciseVisibility(challengeKey, req.user.id)
        : await config.setExerciseVisibility(challengeKey, bool(enabled), req.user.id);
      res.json({ success: true, challengeKey, enabled: result.exercise?.isVisible, ...result });
    } catch (error) { failure(res, error, 'Failed to update challenge visibility'); }
  }
  router.post('/challenges/toggle', requirePermission('challenge_management'), exerciseToggle);
  router.patch('/challenges/:challengeKey/toggle', requirePermission('challenge_management'), exerciseToggle);
  router.post('/challenges/bulk-toggle', requirePermission('challenge_management'), logActivity('admin_bulk_toggle_challenges'), async (req, res) => {
    try { res.json({ success: true, enabled: bool(req.body.enabled), ...(await config.setAllExerciseVisibility(req.body.enabled, req.user.id)) }); }
    catch (error) { failure(res, error, 'Failed to update challenges'); }
  });

  router.put('/challenges/:challengeKey', requirePermission('challenge_management'), logActivity('admin_challenge_update'), async (req, res) => {
    try { res.json({ success: true, message: 'Challenge updated successfully', ...(await config.updateExercise({ key: req.params.challengeKey, ...req.body, userId: req.user.id })) }); }
    catch (error) { failure(res, error, 'Failed to update challenge'); }
  });

  for (const [kind, method] of [['solutions', 'setMasterSolutionVisibility'], ['hints', 'setMasterHintVisibility']]) {
    router.post(`/challenges/${kind}/toggle`, requirePermission('challenge_management'), async (req, res) => {
      try {
        const enabled = bool(req.body[kind === 'solutions' ? 'showSolutions' : 'showHints'] ?? req.body.enabled);
        const result = kind === 'solutions' && req.body.challengeKey === 'reflected_xss_llm'
          ? await xssLegacyRepository.setCanonicalAndLegacyMasterVisibility(enabled, req.user.id)
          : await config[method](req.body.challengeKey, enabled, req.user.id);
        res.json({ success: true, challengeKey: req.body.challengeKey, [kind === 'solutions' ? 'showSolutions' : 'showHints']: enabled, ...result });
      } catch (error) { failure(res, error, `Failed to update ${kind}`); }
    });
  }

  router.get('/config', requirePermission('system_config'), logActivity('admin_config_view'), async (_req, res) => {
    try {
      const rows = await repository.listConfig();
      res.json({ success: true, config: Object.fromEntries(rows.map(row => [row.config_key, {
        value: row.config_value, type: row.config_type, isPublic: row.is_public,
      }])) });
    }
    catch (error) { failure(res, error, 'Failed to fetch configuration'); }
  });
  router.put('/config/:configKey', requirePermission('system_config'), logActivity('admin_config_update'), async (req, res) => {
    try { res.json({ success: true, config: await repository.setConfig(req.params.configKey, req.body.value, req.body.type, req.body.isPublic) }); }
    catch (error) { failure(res, error, 'Failed to update configuration'); }
  });

  router.get('/permissions', requireAdminLevel(2), logActivity('admin_permissions_view'), async (_req, res) => {
    try { res.json({ success: true, permissions: await repository.listPermissions() }); }
    catch (error) { failure(res, error, 'Failed to fetch permissions'); }
  });
  router.post('/permissions', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_permission_grant'), async (req, res) => {
    try {
      const permission = await repository.grantPermission({ userId: req.body.adminId,
        permission: req.body.permissionName, actorId: req.user.id,
        sessionId: req.identitySession?.id, expiresAt: req.body.expiresAt, ipAddress: req.ip });
      if (!permission) return res.status(404).json({ error: 'Administrator not found' });
      res.status(201).json({ success: true, permission });
    } catch (error) { failure(res, error, 'Failed to grant permission'); }
  });
  router.delete('/permissions/:permissionId', requireAdminLevel(2), requirePermission('user_management'),
    logActivity('admin_permission_revoke'), async (req, res) => {
    try {
      if (!(await repository.revokePermissionById(req.params.permissionId,
        { id: req.user.id, sessionId: req.identitySession?.id }))) return res.status(404).json({ error: 'Permission not found' });
      res.json({ success: true, message: 'Permission revoked successfully' });
    } catch (error) { failure(res, error, 'Failed to revoke permission'); }
  });

  router.get('/activity-logs', requireAdminLevel(1), async (req, res) => {
    try { res.json({ success: true, ...(await repository.listActivity(req.query)) }); }
    catch (error) { failure(res, error, 'Failed to fetch activity logs'); }
  });
  router.get('/logs', requirePermission('system_logs'), logActivity('admin_logs_view'), async (req, res) => {
    try { res.json({ success: true, ...(await repository.listActivity(req.query)) }); }
    catch (error) { failure(res, error, 'Failed to fetch logs'); }
  });

  router.get('/dashboard', requireAdminLevel(1), logActivity('admin_dashboard_access'), async (_req, res) => {
    try {
      const [identity, challenges, activity] = await Promise.all([
        repository.dashboardStats(), repository.listExercisesWithStats({ groupDisplay: true }), repository.listActivity({ limit: 10 }),
      ]);
      const visibleChallenges = challenges.filter(item => item.is_visible);
      res.json({ success: true, stats: { totalUsers: identity.total_users, totalStudents: identity.total_students,
        totalAdmins: identity.total_admins, activeChallenges: visibleChallenges.length,
        recentActivities: activity.logs.length, challengeCompletions: visibleChallenges.reduce((sum, item) => sum + item.students_completed, 0),
        studentsWithCompletions: identity.students_with_completions,
        activityWindowHours: identity.activity_window_hours }, recentActivity: activity.logs });
    } catch (error) { failure(res, error, 'Failed to fetch dashboard statistics'); }
  });

  router.get('/dashboard/stats', requireAdminLevel(1), async (_req, res) => {
    try {
      const [identity, exercises, activity] = await Promise.all([
        repository.dashboardStats(), repository.listExercisesWithStats({ groupDisplay: true }), repository.activityStats(),
      ]);
      const visibleExercises = exercises.filter(item => item.is_visible);
      res.json({ success: true, stats: {
        users: { total: identity.total_students, active: identity.active_students_24h,
          new: identity.new_students_24h, activityWindowHours: identity.activity_window_hours },
        challenges: { total: exercises.length, enabled: visibleExercises.length,
          completed: visibleExercises.reduce((sum, item) => sum + item.students_completed, 0) },
        activity: { total: activity.total_activity, successful: activity.total_activity - activity.failed_logins,
          failed: activity.failed_logins }, system: { uptime: process.uptime(), memory: process.memoryUsage() },
      } });
    } catch (error) { failure(res, error, 'Failed to fetch dashboard statistics'); }
  });

  router.get('/activity-stats', requireAdminLevel(1), async (_req, res) => {
    try { res.json({ success: true, stats: await repository.activityStats() }); }
    catch (error) { failure(res, error, 'Failed to fetch activity statistics'); }
  });

  router.get('/llm/health', requireAdminLevel(1), async (req, res) => {
    const lastChecked = new Date().toISOString();
    try {
      const ai = require('../services/multiProviderAIService'), info = ai.getActiveProviderInfo();
      const key = String(info.provider || 'ollama').toLowerCase();
      const deep = req.query.deep === '1' || req.query.deep === 'true';
      const verification = await (deep ? ai.verifyProviderConnection(key) : ai.verifyProviderConnectionLite(key));
      const stats = await repository.llmAuditStats();
      res.json({ success: true, health: { status: verification.healthy ? 'healthy' : verification.available ? 'degraded' : 'unhealthy',
        mode: deep ? 'deep' : 'quick', responseTime: verification.responseTime || 0, lastChecked,
        provider: { ...info, ...verification }, models: info.model ? [{ name: info.model }] : [], providers: [], errors: verification.error ? [verification.error] : [],
        statistics: { totalRequests24h: stats.total_requests, successfulRequests: stats.successful_requests,
          successRate: Math.round(stats.success_rate * 100), uptime: process.uptime() } } });
    } catch (error) { failure(res, error, 'Failed to check LLM health'); }
  });
  router.get('/llm/stats', requireAdminLevel(1), async (_req, res) => {
    try { res.json({ success: true, stats: await repository.llmAuditStats() }); }
    catch (error) { failure(res, error, 'Failed to fetch LLM statistics'); }
  });
  router.get('/ai/stats', requireAdminLevel(1), async (_req, res) => {
    try {
      const stats = await repository.aiStatsByDay();
      const sum = key => stats.reduce((total, row) => total + Number(row[key] || 0), 0);
      res.json({ success: true, stats, summary: { totalRequests: sum('total_requests'), fallbackRequests: sum('fallback_requests'),
        ollamaRequests: sum('ollama_requests'), claudeRequests: sum('claude_requests'), openaiRequests: sum('openai_requests') } });
    } catch (error) { failure(res, error, 'Failed to fetch AI statistics'); }
  });

  router.get('/ai/providers', requireAdminLevel(1), operational.providerStatus);
  router.post('/ai/providers/switch', requireAdminLevel(2), logActivity('admin_ai_provider_switch'), operational.switchProvider);
  router.post('/ai/providers/configure', requireAdminLevel(2), requirePermission('system_config'), logActivity('admin_ai_provider_configure'), operational.configureProvider);
  router.post('/ai/providers/test', requireAdminLevel(1), operational.testProvider);
  router.post('/llm/test', requireAdminLevel(1), logActivity('admin_llm_test'), operational.testLlm);
  router.get('/logs/app', requireAdminLevel(1), operational.appLogs);
  router.get('/logs/llm', requireAdminLevel(1), operational.llmLogs);
  router.get('/logs/stats', requireAdminLevel(1), operational.logStats);
  router.get('/system/monitoring', requireAdminLevel(1), (req, res) => operational.systemMonitoring(req, res, repository));

  router.get('/progress', requirePermission('manage_progress'), logActivity('admin_progress_view'), async (req, res) => {
    try {
      const selected = req.query.studentId ? await repository.getStudent(req.query.studentId) : null;
      const users = req.query.studentId ? (selected ? [selected] : []) : await repository.listStudents();
      const byUser = await progress.getVisibleUsersProgress(users.map(user => user.id));
      const rows = [];
      for (const user of users) for (const item of byUser.get(user.id) || []) {
        if (req.query.challengeKey && ![item.challengeKey, item.workshopKey].includes(req.query.challengeKey)) continue;
        if (req.query.status && item.status !== req.query.status) continue;
        rows.push({ student_id: user.id, ...item });
      }
      res.json({ success: true, progress: rows });
    } catch (error) { failure(res, error, 'Failed to fetch progress data'); }
  });

  router.get('/analytics/progress', requirePermission('manage_progress'), async (_req, res) => {
    try {
      analytics ||= createAdminProgressAnalyticsRepository(stores.pool || adapter.pool);
      res.json(await analytics.getSnapshot());
    } catch (error) { failure(res, error, 'Failed to fetch analytics'); }
  });
  router.get('/analytics/student-progress', requirePermission('manage_progress'), (_req, res) => res.redirect(307, '/api/admin/analytics/progress'));
  router.get('/analytics/platform-stats', requireAdminLevel(1), logActivity('admin_platform_stats'), async (_req, res) => {
    try {
      analytics ||= createAdminProgressAnalyticsRepository(stores.pool || adapter.pool);
      const [identity, exercises, canonical] = await Promise.all([
        repository.dashboardStats(), repository.listExercisesWithStats(), analytics.getSnapshot(),
      ]);
      const metrics = canonical.platformStatistics;
      const categories = {}, difficulties = {};
      for (const item of exercises) {
        categories[item.category] = (categories[item.category] || 0) + 1;
        difficulties[item.difficulty] = (difficulties[item.difficulty] || 0) + 1;
      }
      res.json({ success: true, stats: {
        challenges: { total: exercises.length, active: exercises.filter(item => item.is_visible).length, categories, difficulties },
        students: { total: identity.total_students, active: identity.active_students_24h,
          activityWindowHours: identity.activity_window_hours, registeredToday: metrics.registeredToday, registeredThisWeek: metrics.registeredThisWeek,
          registrationCalendarTimeZone: metrics.calendarTimeZone },
        activity: { totalAttempts: metrics.totalAttempts, attemptDefinition: metrics.attemptDefinition,
          completionsToday: metrics.completionsToday, completionsThisWeek: metrics.completionsThisWeek,
          calendarTimeZone: metrics.calendarTimeZone, averageCompletionTime: metrics.averageCompletionTime,
          averageCompletionTimeStatus: metrics.averageCompletionTimeStatus },
        topChallenges: exercises.slice().sort((a, b) => b.students_completed - a.students_completed).slice(0, 10),
        recentActivity: (await repository.listActivity({ limit: 20 })).logs,
      } });
    } catch (error) { failure(res, error, 'Failed to fetch platform statistics'); }
  });

  router.get('/solutions', requireAdminLevel(1), async (_req, res) => {
    try {
      const solutions = (await repository.listAllSolutions({ includeStandaloneApps: true })).map(row => ({
        id: `${row.workshop_key}:${row.objective_id}`, objective_id: row.objective_id,
        workshopKey: row.workshop_key, challengeKey: row.challenge_key,
        challenge_key: row.challenge_key, challengeName: row.challenge_name, challenge_name: row.challenge_name,
        category: row.category, title: row.solution_content.title || row.label,
        solution_title: row.solution_content.title || row.label, description: row.solution_content.description ?? row.solution_content.approach ?? '',
        solution_description: row.solution_content.description ?? row.solution_content.approach ?? '', steps: row.solution_content.hints || [],
        explanation: row.solution_content.approach || '', tags: row.solution_content.tips || [],
        difficultyLevel: row.solution_content.difficulty || '', examples: row.solution_content.examples || [],
        code: row.solution_content.code || '', references: row.solution_content.references || [],
        estimatedTime: row.solution_content.estimatedTime || '', prerequisites: row.solution_content.prerequisites || [],
        isPublic: row.solution_enabled, is_public: row.solution_enabled,
      }));
      res.json({ success: true, solutions });
    } catch (error) { failure(res, error, 'Failed to fetch challenge solutions'); }
  });
  function splitSolutionId(value) {
    const separator = String(value).indexOf(':');
    if (separator < 1) throw Object.assign(new Error('Unknown solution ID'), { code: 'NOT_FOUND' });
    return [String(value).slice(0, separator), String(value).slice(separator + 1)];
  }
  router.put('/solutions/:solutionId', requirePermission('challenge_management'), logActivity('admin_solution_content_update'), async (req, res) => {
    try {
      const [workshopKey, objectiveId] = splitSolutionId(req.params.solutionId);
      const patch = {};
      if (req.body.solution_title !== undefined) patch.title = req.body.solution_title;
      if (req.body.difficulty_level !== undefined) patch.difficulty = req.body.difficulty_level;
      if (req.body.solution_steps !== undefined) patch.hints = req.body.solution_steps;
      if (req.body.explanation !== undefined) patch.approach = req.body.explanation;
      if (req.body.tags !== undefined) patch.tips = req.body.tags;
      if (req.body.solution_description !== undefined) patch.description = req.body.solution_description;
      if (req.body.solution_code !== undefined) patch.code = req.body.solution_code;
      if (req.body.reference_links !== undefined) patch.references = req.body.reference_links;
      if (req.body.estimated_time !== undefined) patch.estimatedTime = req.body.estimated_time;
      if (req.body.prerequisites !== undefined) patch.prerequisites = req.body.prerequisites;
      if (req.body.examples !== undefined) patch.examples = req.body.examples;
      await config.saveSolutionEditor(workshopKey, objectiveId, patch, {
        isPublic: req.body.is_public, userId: req.user.id,
      });
      res.json({ success: true, message: 'Solution updated successfully' });
    } catch (error) { failure(res, error, 'Failed to update solution'); }
  });
  router.patch('/solutions/:solutionId/visibility', requirePermission('challenge_management'), logActivity('admin_solution_visibility_toggle'), async (req, res) => {
    try {
      const [workshopKey, objectiveId] = splitSolutionId(req.params.solutionId);
      const result = await config.setObjectiveSolutionVisibility(workshopKey, objectiveId,
        bool(req.body.isPublic ?? req.body.enabled), req.user.id);
      res.json({ success: true, ...result });
    } catch (error) { failure(res, error, 'Failed to update solution visibility'); }
  });

  router.get('/security/settings', requireAdminLevel(2), async (_req, res) => {
    try {
      const rows = (await repository.listConfig()).filter(row => row.config_key.startsWith('security.'));
      res.json({ success: true, settings: Object.fromEntries(rows.map(row => [row.config_key.slice(9), { value: row.config_value, description: '' }])) });
    } catch (error) { failure(res, error, 'Failed to fetch security settings'); }
  });
  router.put('/security/settings', requireAdminLevel(2), logActivity('admin_security_settings_update'), async (req, res) => {
    if (!req.body.settings || typeof req.body.settings !== 'object') return res.status(400).json({ error: 'Invalid settings format' });
    try {
      await Promise.all(Object.entries(req.body.settings).map(([key, value]) => repository.setConfig(`security.${key}`, value.value, 'string', false)));
      res.json({ success: true, message: 'Security settings updated successfully' });
    } catch (error) { failure(res, error, 'Failed to update security settings'); }
  });

  const requireChallengeResetPermission = (req, res, next) => req.body?.resetType === 'challenges'
    ? requirePermission('manage_progress')(req, res, next) : next();
  router.post('/database/reset', requireAdminLevel(2), requireChallengeResetPermission,
    logActivity('admin_database_reset_request'), async (req, res) => {
    const { resetType, confirmPassword } = req.body || {};
    if (!['challenges', 'logs'].includes(resetType)) return res.status(400).json({ error: 'Choose workshop data or old activity logs; full database reset is not supported here', code: 'INVALID_RESET_TYPE' });
    if (typeof confirmPassword !== 'string' || !confirmPassword) return res.status(400).json({ error: 'Current administrator password is required' });
    try {
      const credential = await adapter.repository.findCredentialById(req.user.id);
      if (!credential || !await bcrypt.compare(confirmPassword, credential.password)) return res.status(403).json({ error: 'Administrator password confirmation failed' });
      if (resetType === 'logs') {
        const deleted = await repository.clearOldActivityLogs();
        return res.json({ success: true, resetType, message: `${deleted} activity log entries older than seven days removed. Workshop progress was preserved.`, results: { deletedActivityLogs: deleted, backupsCreated: [], tablesReset: [], errors: [] } });
      }
      await resetService.resetAll(require('../services/workshopResetRequest').workshopResetRequest(req,res));
      return res.json({ success: true, resetType, message: 'Canonical workshop data and progress reset. User accounts, CTF and SecureShop data were preserved. No backup was created.', results: { backupsCreated: [], tablesReset: [], errors: [] } });
    } catch (error) { return failure(res, error, 'Administrative reset failed'); }
  });
  for (const endpoint of ['/system/reset', '/workshops/reset-all-progress']) {
    router.post(endpoint, requireAdminLevel(2), (_req, res) => res.status(409).json({
      success: false, code: 'CONFIRMED_RESET_REQUIRED',
      error: 'Use /api/admin/database/reset with resetType challenges and the current administrator password',
    }));
  }
  for (const endpoint of ['/database/initialize', '/database/initilize']) router.post(endpoint, requireAdminLevel(2), (_req, res) =>
    res.status(409).json({ success: false, error: 'PostgreSQL schema migrations must run through the migration command' }));

  router.get('/students/:studentId/progress', requirePermission('manage_progress'), async (req, res) => {
    try {
      const student = await repository.getStudent(req.params.studentId);
      if (!student) {
        return res.status(404).json({ error: 'Student not found' });
      }
      const challenges = projectWorkshopChallenges(await progress.getVisibleUserProgress(req.params.studentId));
      const completedChallenges = challenges.filter(row => row.status === 'completed').length;
      const workshopObjectives = Object.fromEntries(challenges.map(challenge => [
        challenge.workshopKey,
        (challenge.objectives || []).map(objective => ({
          workshop_key: challenge.workshopKey,
          objective_id: objective.id,
          objective_label: objective.label || objective.text || objective.id,
          objective_category: null,
          completed: objective.completed === true,
          completed_at: objective.completedAt || objective.completed_at || null,
        })),
      ]));
      res.json({
        success: true,
        student,
        progress: challenges.map(challenge => ({
          id: challenge.id,
          challenge_name: challenge.name || challenge.title || challenge.id,
          status: challenge.status,
          score: null,
          challenge_max_score: null,
          difficulty_level: challenge.difficulty,
          category: challenge.category,
          time_spent_seconds: challenge.timeSpentSeconds,
        })),
        stats: {
          totalChallenges: challenges.length,
          completedChallenges,
          inProgressChallenges: challenges.filter(row => row.status === 'in_progress').length,
          totalTimeSpent: challenges.reduce((sum, row) => sum + (Number(row.timeSpentSeconds) || 0), 0),
          totalObjectivesCompleted: challenges.reduce((sum, row) => sum + (Number(row.completedObjectiveCount) || 0), 0),
          totalScore: null,
          averageScore: null,
          pointsAvailable: false,
        },
        workshopObjectives,
        pointsAvailable: false,
      });
    }
    catch (error) { failure(res, error, 'Failed to fetch student progress'); }
  });
  router.get('/student-workshop-view/:studentId', requirePermission('manage_progress'), logActivity('admin_student_workshop_view'), async (req, res) => {
    try {
      const student = await repository.getStudent(req.params.studentId);
      if (!student) return res.status(404).json({ error: 'Student not found' });
      const [challenges, activity] = await Promise.all([
        progress.getVisibleUserProgress(req.params.studentId),
        readAdminWorkshopActivity(stores.pool || adapter.pool, [student.id]),
      ]);
      res.json({ success: true, ...projectAdminWorkshopView(student, challenges, activity.get(student.id)) });
    } catch (error) { failure(res, error, 'Failed to fetch student workshop view'); }
  });
  router.get('/all-students-workshop-view', requirePermission('manage_progress'), logActivity('admin_all_students_workshop_view'), async (_req, res) => {
    try {
      const students = await repository.listStudents();
      const ids = students.map(user => user.id);
      const [byUser, activity] = await Promise.all([
        progress.getVisibleUsersProgress(ids), readAdminWorkshopActivity(stores.pool || adapter.pool, ids),
      ]);
      const projections = students.map(student => {
        const view = projectAdminWorkshopView(student, byUser.get(student.id) || [], activity.get(student.id));
        return { ...student, ...view.overview, challenges: view.challenges, workshops: view.challenges, lastActivity: view.lastActivity };
      });
      res.json({ success: true, totalStudents: projections.length,
        totalChallenges: projections[0]?.totalChallenges || 0, students: projections });
    } catch (error) { failure(res, error, 'Failed to fetch workshop view'); }
  });

  router.get('/workshops/reset-operations', requirePermission('manage_progress'), async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const keys=Object.keys(req.query);let scope;
    if(keys.length){
      const {requestKind,workshopKey}=req.query;
      if(keys.some(key=>!['requestKind','workshopKey'].includes(key)) || !['all','workshop'].includes(requestKind)
        || (requestKind==='all'&&workshopKey!==undefined)
        || (requestKind==='workshop'&&(typeof workshopKey!=='string'||!/^[a-z][a-z0-9_]{0,95}$/.test(workshopKey))))
        return res.status(400).json({error:'Invalid reset recovery scope',code:'BAD_REQUEST'});
      scope={requestKind,...(requestKind==='workshop'?{workshopKey}:{})};
    }
    try {
      if (typeof resetService.listPendingBulkResets !== 'function') {
        return res.status(503).json({ error: 'Durable bulk reset storage required', code: 'RESET_STORAGE_NOT_READY' });
      }
      const actorRequest = require('../services/workshopResetRequest').workshopResetActorRequest(req);
      const operations = await resetService.listPendingBulkResets({ actorRequest, ...(scope?{scope}:{}) });
      res.json({ success: true, operations });
    } catch (error) { failure(res, error, 'Failed to read pending reset operations'); }
  });

  router.post('/students/:studentId/workshops/:workshopKey/reset', requirePermission('manage_progress'), async (req, res) => {
    try {
      if (!await repository.getMutableStudent(req.params.studentId)) return res.status(404).json({ error: 'Student not found' });
      const input = { userId: req.params.studentId, workshopKey: req.params.workshopKey, ...require('../services/workshopResetRequest').workshopResetRequest(req,res) };
      const result = await resetService.resetAdministrativeStudent(input);
      res.json({ success: true, message: 'Workshop progress reset successfully', result });
    } catch (error) { failure(res, error, 'Failed to reset workshop progress'); }
  });
  router.post('/workshops/:workshopKey/reset-all-students', requirePermission('manage_progress'), async (req, res) => {
    try {
      await resetService.resetWorkshop({ workshopKey: req.params.workshopKey, ...require('../services/workshopResetRequest').workshopResetRequest(req,res) });
      res.json({ success: true, message: 'Workshop progress reset for all students' });
    } catch (error) { failure(res, error, 'Failed to reset workshop progress'); }
  });

  router.get('/workshops/:workshopKey/objectives', requireAdminLevel(1), async (req, res) => {
    try {
      const snapshot = await config.getSnapshot({ includeRaw: true }), exercise = snapshot.exercises[req.params.workshopKey];
      if (!exercise) return res.status(404).json({ error: 'Workshop not found' });
      res.json({ success: true, workshopKey: exercise.workshopKey,
        objectives: Object.entries(exercise.objectives).map(([objective_id, value]) => ({
          workshopKey: value.workshopKey, objective_id, label: value.label,
          is_enabled: value.raw.objectiveEnabled, hint_enabled: value.raw.hintEnabled,
          solutions_enabled: value.raw.solutionEnabled, has_hint_content: value.hasHintContent,
        })) });
    } catch (error) { failure(res, error, 'Failed to fetch objectives'); }
  });
  router.post('/workshops/:workshopKey/objectives/:objectiveId/toggle', requirePermission('challenge_management'), async (req, res) => {
    try { res.json({ success: true, ...(await config.setObjectiveVisibility(req.params.workshopKey, req.params.objectiveId, bool(req.body.enabled), req.user.id)) }); }
    catch (error) { failure(res, error, 'Failed to update objective'); }
  });
  router.post('/workshops/:workshopKey/objectives/bulk-toggle', requirePermission('challenge_management'), async (req, res) => {
    try {
      const enabled = bool(req.body.enabled);
      res.json({ success: true, enabled, ...(await config.setAllObjectiveVisibility(req.params.workshopKey, enabled, req.user.id)) });
    } catch (error) { failure(res, error, 'Failed to update objectives'); }
  });
  router.get('/workshops/:workshopKey/hints', requireAdminLevel(1), async (req, res) => {
    try { res.json({ success: true, hints: await config.getHintVisibilityMap(req.params.workshopKey) }); }
    catch (error) { failure(res, error, 'Failed to fetch hints'); }
  });
  router.post('/workshops/:workshopKey/hints/:objectiveId/toggle', requirePermission('challenge_management'), async (req, res) => {
    try { res.json({ success: true, ...(await config.setObjectiveHintVisibility(req.params.workshopKey, req.params.objectiveId, bool(req.body.enabled), req.user.id)) }); }
    catch (error) { failure(res, error, 'Failed to update hint'); }
  });
  router.post('/workshops/:workshopKey/hints/bulk-toggle', requirePermission('challenge_management'), async (req, res) => {
    try { res.json({ success: true, ...(await config.setMasterHintVisibility(req.params.workshopKey, bool(req.body.enabled), req.user.id)) }); }
    catch (error) { failure(res, error, 'Failed to update hints'); }
  });

  // Four-tab XSS solution API retained for older authenticated admin clients.
  // These flags are independent from the canonical 12-objective solution gates.
  router.get('/xss-workshop/solutions', requireAdminLevel(1), async (_req, res) => {
    try {
      const rows = await xssLegacyRepository.listSolutions();
      res.json({ success: true, challenges: rows.map(row => ({
        challengeId: row.challenge_id, solutionsEnabled: !!row.solutions_enabled,
        enabledBy: row.enabled_by, enabledAt: row.enabled_at, updatedAt: row.updated_at,
        title: row.title, difficulty: row.difficulty,
      })) });
    } catch (error) { failure(res, error, 'Failed to fetch XSS workshop solutions'); }
  });
  router.post('/xss-workshop/solutions/toggle', requirePermission('challenge_management'), logActivity('admin_xss_solution_toggle'), async (req, res) => {
    const { challengeId, enabled } = req.body;
    if (!challengeId || !XSS_LEGACY_IDS.includes(challengeId)) return res.status(400).json({ error: 'Valid challengeId is required' });
    try {
      await xssLegacyRepository.setVisibility(challengeId, !!enabled, req.user.id);
      res.json({ success: true, challengeId, enabled: !!enabled });
    } catch (error) { failure(res, error, 'Failed to update visibility'); }
  });
  router.post('/xss-workshop/solutions/bulk', requirePermission('challenge_management'), logActivity('admin_xss_solution_bulk'), async (req, res) => {
    const enabled = !!req.body.enabled;
    try {
      const updated = await xssLegacyRepository.setAllVisibility(enabled, req.user.id);
      res.json({ success: true, enabled, updated });
    } catch (error) { failure(res, error, 'Failed to update visibility'); }
  });
  router.get('/xss-workshop/solutions/preview/:challengeId', requireAdminLevel(1), async (req, res) => {
    try {
      const solution = await xssLegacyRepository.getSolution(req.params.challengeId);
      if (!solution) return res.status(404).json({ error: 'Solution not found' });
      try {
        solution.hints = JSON.parse(solution.hints || '[]');
        solution.examples = JSON.parse(solution.examples || '[]');
        solution.tips = JSON.parse(solution.tips || '[]');
      } catch {}
      res.json({ success: true, solution });
    } catch (error) { failure(res, error, 'Failed to fetch solution'); }
  });
  router.post('/xss-workshop/solutions/:challengeId', requirePermission('challenge_management'), logActivity('admin_xss_solution_update'), async (req, res) => {
    const { title, difficulty, hints, examples, approach, tips } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    try {
      await xssLegacyRepository.updateSolution(req.params.challengeId, {
        title, difficulty,
        hints: Array.isArray(hints) ? JSON.stringify(hints) : (hints || '[]'),
        examples: Array.isArray(examples) ? JSON.stringify(examples) : examples,
        approach, tips: Array.isArray(tips) ? JSON.stringify(tips) : tips,
      });
      res.json({ success: true, message: 'Solution updated successfully' });
    } catch (error) { failure(res, error, 'Failed to update solution content'); }
  });

  for (const [prefix, workshopKey] of solutionRoutes) {
    const base = `/${prefix}${prefix.includes('objective-solutions') ? '' : '/solutions'}`;
    router.get(base, requireAdminLevel(1), async (_req, res) => {
      try {
        const rows = await repository.listSolutionObjectives(workshopKey);
        if (prefix === 'pi-workshop') return res.json({ success: true, challenges: rows.map(row => ({
          challengeId: row.objective_id, solutionsEnabled: row.solutions_enabled,
        })) });
        if (prefix === 'supply-chain-workshop') return res.json({ success: true, solutions: rows });
        if (prefix === 'finflow-workshop') return res.json({ success: true, objectives: rows.map(row => ({
          objectiveId: row.objective_id, solutionsEnabled: row.solutions_enabled, title: row.title, difficulty: row.difficulty,
        })) });
        return res.json({ success: true, objectives: rows });
      }
      catch (error) { failure(res, error, 'Failed to fetch solutions'); }
    });
    router.get(`${base}/preview/:objectiveId`, requireAdminLevel(1), async (req, res) => {
      try {
        const rows = await repository.listSolutionObjectives(workshopKey), row = rows.find(item => item.objective_id === req.params.objectiveId);
        if (!row?.solution_content) return res.status(404).json({ error: 'Solution not found' });
        res.json({ success: true, solution: { objective_id: row.objective_id, ...row.solution_content } });
      } catch (error) { failure(res, error, 'Failed to fetch solution'); }
    });
    router.post(`${base}/toggle`, requirePermission('challenge_management'), async (req, res) => {
      try { res.json({ success: true, ...(await config.setObjectiveSolutionVisibility(workshopKey, req.body.objectiveId || req.body.challengeId, bool(req.body.enabled), req.user.id)) }); }
      catch (error) { failure(res, error, 'Failed to update solution'); }
    });
    router.post(`${base}/bulk`, requirePermission('challenge_management'), async (req, res) => {
      try { res.json({ success: true, ...(await config.setMasterSolutionVisibility(workshopKey, bool(req.body.enabled), req.user.id)) }); }
      catch (error) { failure(res, error, 'Failed to update solutions'); }
    });
    router.post(`${base}/:objectiveId`, requirePermission('challenge_management'), async (req, res) => {
      try { res.json({ success: true, ...(await config.updateSolutionContent(workshopKey, req.params.objectiveId, req.body)) }); }
      catch (error) { failure(res, error, 'Failed to update solution'); }
    });
    router.post(`${base}/:objectiveId/toggle`, requirePermission('challenge_management'), async (req, res) => {
      try { res.json({ success: true, ...(await config.setObjectiveSolutionVisibility(workshopKey, req.params.objectiveId, bool(req.body.enabled), req.user.id)) }); }
      catch (error) { failure(res, error, 'Failed to update solution'); }
    });
  }

  return router;
}

module.exports = { createPostgresAdminRouter };

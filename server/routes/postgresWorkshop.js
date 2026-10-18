'use strict';

const express = require('express');
const { hasAdminLevel } = require('../middleware/postgresAdminAuth');
const {
  createWorkshopProgressHandlers
} = require('./workshopProgressHandlers');
const {
  createWorkshopTimeHandlers
} = require('./workshopTimeHandlers');
const { createPostgresAdminRepository } = require('../database/postgres/adminRepository');
const { projectWorkshopChallenge } = require('../services/workshopChallengeProjection');
function createPostgresWorkshopRouter({
  stores,
  authenticateToken,
  resetService,
  accountRepository,
  requirePermission
}) {
  accountRepository ||= createPostgresAdminRepository(stores.pool);
  const permission = typeof requirePermission === 'function'
    ? requirePermission
    : () => (_req, res) => res.status(503).json({ error: 'Permission checks unavailable' });
  const router = express.Router();
  router.use(authenticateToken);
  const handlers = createWorkshopProgressHandlers({
    progressService: stores.progress,
    getActiveDays: async id => Number((await stores.pool.query('SELECT count(DISTINCT (timestamp AT TIME ZONE \'UTC\')::date) AS count FROM identity.activity_logs WHERE user_id=$1', [id])).rows[0].count)
  });
  router.get('/student/stats', handlers.getStudentStats);
  router.get('/progress', handlers.getProgress);
  router.get('/challenges', handlers.getChallenges);
  // The separate app keeps its owned curriculum without entering workshop totals.
  router.get('/applications/secureshop', async (req, res, next) => {
    try {
      const challenge = await stores.progress.getVisibleWorkshopProgress(req.user.id, 'secureshop_agent_security');
      res.json({ success: true, challenges: challenge ? [projectWorkshopChallenge(challenge)] : [] });
    } catch (error) { next(error); }
  });
  router.post('/time/heartbeat', createWorkshopTimeHandlers({
    timeService: stores.progress
  }).recordHeartbeat);
  router.get('/time/summary', async (req, res, next) => {
    try {
      const rows = await stores.progress.getVisibleUserProgress(req.user.id);
      res.json({
        summary: Object.fromEntries(rows.map(row => [row.workshopKey, row.timeSpentSeconds]))
      });
    } catch (error) {
      next(error);
    }
  });
  router.get('/objective/completed/:challengeId', async (req, res, next) => {
    try {
      const row = await stores.progress.getWorkshopProgress(req.user.id, req.params.challengeId);
      res.json({
        completedObjectives: row?.objectives.filter(objective => objective.completed).map(objective => objective.id) || []
      });
    } catch (error) {
      next(error);
    }
  });
  const route = handler => async (req, res, next) => {
    try {
      await handler(req, res);
    } catch (error) {
      next(error);
    }
  };
  router.get('/student/activity', route(async (req, res) => {
    const rows = (await stores.pool.query('SELECT action_type, action_details, timestamp FROM identity.activity_logs WHERE user_id=$1 ORDER BY timestamp DESC LIMIT 10', [req.user.id])).rows;
    res.json({
      success: true,
      activities: rows.map(row => {
        const minutes = Math.max(0, Math.floor((Date.now() - row.timestamp.getTime()) / 60000));
        return {
          type: row.action_type,
          title: row.action_details?.url || row.action_type,
          timeAgo: minutes < 1 ? 'Just now' : minutes < 60 ? `${minutes}m ago` : minutes < 1440 ? `${Math.floor(minutes / 60)}h ago` : `${Math.floor(minutes / 1440)}d ago`
        };
      })
    });
  }));
  router.get('/user-activity', route(async (req, res) => {
    const [challenges, logs, users] = await Promise.all([stores.progress.getVisibleUserProgress(req.user.id), stores.pool.query('SELECT id, action_type, timestamp FROM identity.activity_logs WHERE user_id=$1 ORDER BY timestamp DESC LIMIT 30', [req.user.id]), stores.pool.query('SELECT last_login FROM identity.users WHERE id=$1', [req.user.id])]);
    const objectives = challenges.flatMap(challenge => challenge.objectives.filter(o => o.completed).map(o => ({
      id: `obj_${challenge.workshopKey}_${o.id}`,
      type: 'challenge',
      title: `Completed: ${o.label}`,
      description: `in ${challenge.title}`,
      timestamp: o.completedAt,
      completed_at: o.completedAt,
      workshop_key: challenge.workshopKey,
      objective_id: o.id,
      objective_label: o.label,
      workshop_name: challenge.title
    })));
    const activity = [...objectives, ...logs.rows.map(row => ({
      id: `log_${row.id}`,
      type: /login|logout/.test(row.action_type) ? 'login' : 'profile',
      title: row.action_type.replace(/_/g, ' '),
      description: '',
      timestamp: row.timestamp
    }))].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    res.json({
      activity,
      lastLogin: users.rows[0]?.last_login || null
    });
  }));
  router.post('/objective/complete', route(async (req, res) => {
    const {
      challengeId,
      objectiveId
    } = req.body || {};
    if (!challengeId || !objectiveId) return res.status(400).json({
      error: 'Challenge ID and Objective ID are required'
    });
    if (require('../config/workshopCatalog').toWorkshopKey(challengeId) === 'direct_prompt_injection') return res.status(410).json({
      error: 'Direct Prompt Injection progress is graded by /chat',
      code: 'DPI_SERVER_GRADED'
    });
    return res.status(409).json({ error: 'Objective completion requires a server-observed, judged attempt in the exercise.', code: 'JUDGED_ATTEMPT_REQUIRED' });
  }));
  router.post('/progress/reset/:workshopKey', route(async (req, res) => {
    const reset = resetService || require('../services/postgresWorkshopResetService').getPostgresWorkshopResetService();
    await reset.resetStudent({
      userId: req.user.id,
      workshopKey: req.params.workshopKey,
      ...require('../services/workshopResetRequest').workshopResetRequest(req,res)
    });
    res.json({
      success: true
    });
  }));
  router.post('/progress/:userId/:challengeId', (req, res) => res.status(410).json({
    error: 'Progress is derived from objective completions',
    code: 'PROGRESS_MUTATION_RETIRED'
  }));
  router.use('/instructor', (req, res, next) => hasAdminLevel(req.user, 1) ? next() : res.status(403).json({
    error: 'Access denied'
  }));
  router.get('/instructor/students', permission('manage_progress'), route(async (req, res) => {
    const users = (await stores.pool.query("SELECT id,username,email,is_active,created_at,last_login FROM identity.users WHERE role IN ('student','user') ORDER BY id")).rows;
    const all = await stores.progress.getVisibleUsersProgress(users.map(user => user.id));
    const students = users.map(user => {
      const challenges = all.get(user.id) || [],
        total = challenges.reduce((sum, c) => sum + c.objectiveCount, 0),
        complete = challenges.reduce((sum, c) => sum + c.completedObjectiveCount, 0);
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        enabled: !!user.is_active,
        status: user.is_active ? 'active' : 'inactive',
        joinedDate: user.created_at,
        lastActive: user.last_login,
        progress: total ? Math.round(complete / total * 100) : 0,
        completedChallenges: challenges.filter(c => c.completed).length,
        totalChallenges: challenges.length,
        totalTimeSpent: challenges.reduce((sum, c) => sum + c.timeSpentSeconds, 0),
        challengeProgress: Object.fromEntries(challenges.map(c => [c.workshopKey, c]))
      };
    });
    res.json({
      success: true,
      students,
      stats: {
        totalStudents: students.length,
        activeStudents: students.filter(s => s.enabled).length,
        completedChallenges: students.reduce((sum, s) => sum + s.completedChallenges, 0),
        averageProgress: students.length ? Math.round(students.reduce((sum, s) => sum + s.progress, 0) / students.length) : 0
      }
    });
  }));
  router.get('/instructor/challenges', permission('challenge_management'), route(async (req, res) => res.json({
    success: true,
    challenges: await stores.progress.getInstructorProgress(req.user.id)
  })));
  router.put('/instructor/challenges/:challengeId/toggle', permission('challenge_management'), route(async (req, res) => {
    await stores.config.setExerciseVisibility(req.params.challengeId, req.body?.enabled, req.user.id);
    res.json({
      success: true,
      challengeId: req.params.challengeId,
      enabled: req.body.enabled,
      message: `Challenge ${req.body.enabled ? 'enabled' : 'disabled'} successfully`
    });
  }));
  router.put('/instructor/students/:studentId/toggle', permission('user_management'), route(async (req, res) => {
    const id = Number(req.params.studentId),
      enabled = req.body?.enabled;
    if (!Number.isInteger(id) || id <= 0 || typeof enabled !== 'boolean') return res.status(400).json({
      error: 'A valid student ID and boolean enabled are required'
    });
    if (id === Number(req.user.id)) return res.status(404).json({
      error: 'Student not found or not eligible'
    });
    const changed = await accountRepository.setStudentActive({ userId: id, enabled });
    if (!changed) return res.status(404).json({
      error: 'Student not found or not eligible'
    });
    res.json({
      success: true,
      studentId: req.params.studentId,
      enabled,
      message: `Student ${enabled ? 'enabled' : 'disabled'} successfully`
    });
  }));
  router.post('/instructor/reset-progress/:studentId', permission('manage_progress'), route(async (req, res) => {
    const studentId = Number(req.params.studentId);
    if (!Number.isInteger(studentId) || studentId <= 0) return res.status(400).json({ error: 'A valid student ID is required' });
    if (!await accountRepository.getMutableStudent(studentId)) return res.status(404).json({ error: 'Student not found' });
    const reset = resetService || require('../services/postgresWorkshopResetService').getPostgresWorkshopResetService();
    const workshops = await stores.progress.getUserProgress(studentId);
    for (const workshop of workshops) reset.assertSupported(workshop.workshopKey);
    const authority=require('../services/workshopResetRequest').workshopResetRequest(req,res);
    for (const workshop of workshops) await reset.resetStudent({
      userId: studentId,
      workshopKey: workshop.workshopKey,
      actorRequest:authority.actorRequest,operationId:require('../services/workshopResetRequest').childResetOperation(authority.operationId,workshop.workshopKey)
    });
    res.json({
      success: true,
      message: 'Student progress reset successfully'
    });
  }));
  router.use((error, req, res, next) => {
    const status = error.statusCode || {
      BAD_REQUEST: 400,
      AUTH_REQUIRED: 401,
      NOT_FOUND: 404,
      OBJECTIVE_DISABLED: 409,
      STALE_GENERATION: 409
    }[error.code] || 500;
    res.status(status).json({
      error: status === 500 ? 'Workshop operation failed' : error.message,
      ...(error.code ? {
        code: error.code
      } : {})
    });
  });
  return router;
}
module.exports = {
  createPostgresWorkshopRouter
};

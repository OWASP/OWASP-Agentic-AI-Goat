'use strict';
const { projectWorkshopChallenges } = require('./workshopChallengeProjection');

// Consume the same visible, enabled-objective projection as student dashboards.
// PostgreSQL has no canonical workshop points ledger: never invent a score.
function projectAdminWorkshopView(student, challenges, activity = {}) {
  challenges = projectWorkshopChallenges(challenges);
  const completedChallenges = challenges.filter(row => row.status === 'completed').length;
  const overview = {
    totalChallenges: challenges.length,
    totalSystemChallenges: challenges.length,
    completedChallenges,
    inProgressChallenges: challenges.filter(row => row.status === 'in_progress').length,
    availableChallenges: challenges.length - completedChallenges,
    totalObjectives: challenges.reduce((sum, row) => sum + row.objectiveCount, 0),
    completedObjectives: challenges.reduce((sum, row) => sum + row.completedObjectiveCount, 0),
    totalTimeSeconds: challenges.reduce((sum, row) => sum + row.timeSpentSeconds, 0),
    totalPoints: null,
    pointsAvailable: false,
    // Existing student dashboard calls the number of distinct UTC active days "streak".
    streak: Number(activity.active_days) || 0,
    completionPercentage: challenges.length ? Math.round(completedChallenges / challenges.length * 100) : 0,
  };
  const studentIdentity = {
    id: student.id,
    username: student.username,
    fullName: student.full_name || null,
    joined: student.created_at || null,
  };
  return { student: studentIdentity, overview, challenges,
    workshops: challenges, lastActivity: activity.last_activity || null };
}

async function readAdminWorkshopActivity(pool, userIds) {
  if (!userIds.length) return new Map();
  const result = await pool.query(`SELECT user_id,
    count(DISTINCT (timestamp AT TIME ZONE 'UTC')::date)::integer AS active_days,
    max(timestamp) AS last_activity FROM identity.activity_logs
    WHERE user_id=ANY($1::integer[]) GROUP BY user_id`, [userIds]);
  return new Map(result.rows.map(row => [row.user_id, row]));
}

module.exports = { projectAdminWorkshopView, readAdminWorkshopActivity };

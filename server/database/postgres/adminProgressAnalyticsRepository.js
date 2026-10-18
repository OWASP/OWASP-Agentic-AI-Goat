'use strict';

const { consistentRead } = require('./workshopPlatformSupport');
const { liveWorkshopTimeCondition } = require('./workshopProgressTimePredicate');
const { workshopSurfaceSqlCondition } = require('../../config/workshopCatalog');

const POPULATION = "u.role='student' AND u.is_active=1";
const VISIBLE_EXERCISE = `e.catalog_active=true AND e.is_visible=true AND ${workshopSurfaceSqlCondition('e.workshop_key')}`;
const ENABLED_OBJECTIVE = 'o.catalog_active=true AND o.is_enabled=true';
const LOGICAL_WORKSHOP_KEY = key => `CASE WHEN ${key}='xss_email_builder' THEN 'xss_workshop' ELSE ${key} END`;
const LIVE_TIME = liveWorkshopTimeCondition('t');
const SNAPSHOT_NOW = 'transaction_timestamp()';
const UTC_DAY_START = `(date_trunc('day',${SNAPSHOT_NOW} AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`;
const UTC_WEEK_START = `(date_trunc('week',${SNAPSHOT_NOW} AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')`;
const UTC_30_DAY_START = `(((${SNAPSHOT_NOW} AT TIME ZONE 'UTC')::date-29)::timestamp AT TIME ZONE 'UTC')`;
const INSTANCE_READINESS_SQL = `/* admin-progress-analytics:instance-readiness */
  SELECT to_regclass('identity.secureshop_progress_cleanup_history') IS NOT NULL AS history,
    EXISTS(SELECT 1 FROM pg_attribute
      WHERE attrelid='workshop_platform.time_tracking'::regclass
        AND attname='platform_launch_id' AND NOT attisdropped) AS launch_scope,
    EXISTS(SELECT 1 FROM pg_attribute
      WHERE attrelid='workshop_platform.time_tracking'::regclass
        AND attname='platform_launch_generation' AND NOT attisdropped) AS generation_scope`;

function buildSql(liveTimeCondition = LIVE_TIME) {
  return Object.freeze({
  overview: `/* admin-progress-analytics:overview */
    WITH population AS (
      SELECT u.id,u.last_login,u.created_at FROM identity.users u WHERE ${POPULATION}
    ), visible_objectives AS (
      SELECT o.workshop_key,o.objective_id
      FROM workshop_platform.objectives o
      JOIN workshop_platform.exercises e ON e.workshop_key=o.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${ENABLED_OBJECTIVE}
    ), eligible_completions AS (
      SELECT c.user_id,c.workshop_key,c.objective_id,c.completed_at
      FROM workshop_platform.completions c
      JOIN population p ON p.id=c.user_id
      JOIN visible_objectives o USING(workshop_key,objective_id)
    ), eligible_time AS (
      SELECT t.user_id,t.duration_seconds
      FROM workshop_platform.time_tracking t
      JOIN population p ON p.id=t.user_id
      JOIN workshop_platform.exercises e ON e.workshop_key=t.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${liveTimeCondition}
    ), time_by_student AS (
      SELECT user_id,sum(duration_seconds)::bigint AS seconds FROM eligible_time GROUP BY user_id
    )
    SELECT (SELECT count(*)::integer FROM population) AS total_students,
      (SELECT count(*)::integer FROM population WHERE created_at BETWEEN ${UTC_DAY_START} AND ${SNAPSHOT_NOW}) AS registered_today,
      (SELECT count(*)::integer FROM population WHERE created_at BETWEEN ${UTC_WEEK_START} AND ${SNAPSHOT_NOW}) AS registered_this_week,
      (SELECT count(*)::integer FROM eligible_completions WHERE completed_at BETWEEN ${UTC_DAY_START} AND ${SNAPSHOT_NOW}) AS completions_today,
      (SELECT count(*)::integer FROM workshop_platform.objective_judgments j
        JOIN population p ON p.id=j.user_id
        JOIN visible_objectives o USING(workshop_key,objective_id)
        WHERE j.created_at<=${SNAPSHOT_NOW}) AS total_evaluation_attempts,
      (SELECT count(*)::integer FROM population
        WHERE last_login BETWEEN ${UTC_30_DAY_START} AND ${SNAPSHOT_NOW}) AS active_students,
      (SELECT count(*)::integer FROM visible_objectives) AS total_enabled_objectives,
      (SELECT count(*)::integer FROM eligible_completions) AS total_objective_completions,
      (SELECT count(*)::integer FROM eligible_completions
        WHERE completed_at BETWEEN ${UTC_WEEK_START} AND ${SNAPSHOT_NOW}) AS completions_this_week,
      (SELECT avg(COALESCE(t.seconds,0))/60.0
        FROM population p LEFT JOIN time_by_student t ON t.user_id=p.id) AS avg_session_minutes`,

  challenges: `/* admin-progress-analytics:challenges */
    WITH population AS (
      SELECT u.id FROM identity.users u WHERE ${POPULATION}
    ), catalog_members AS (
      SELECT ${LOGICAL_WORKSHOP_KEY('e.workshop_key')} AS workshop_key,
        e.challenge_key,e.challenge_name,e.difficulty,e.ordinal,
        e.workshop_key='xss_workshop' AS preferred,
        count(o.objective_id)::integer AS enabled_objectives
      FROM workshop_platform.exercises e
      LEFT JOIN workshop_platform.objectives o ON o.workshop_key=e.workshop_key
        AND ${ENABLED_OBJECTIVE}
      WHERE ${VISIBLE_EXERCISE}
      GROUP BY e.workshop_key,e.challenge_key,e.challenge_name,e.difficulty,e.ordinal
    ), catalog AS (
      SELECT workshop_key,
        (array_agg(challenge_key ORDER BY preferred DESC,ordinal))[1] AS challenge_key,
        (array_agg(challenge_name ORDER BY preferred DESC,ordinal))[1] AS challenge_name,
        (array_agg(difficulty ORDER BY preferred DESC,ordinal))[1] AS difficulty,
        (array_agg(ordinal ORDER BY preferred DESC,ordinal))[1] AS ordinal,
        sum(enabled_objectives)::integer AS enabled_objectives
      FROM catalog_members GROUP BY workshop_key
    ), eligible_completions AS (
      SELECT c.user_id,${LOGICAL_WORKSHOP_KEY('c.workshop_key')} AS workshop_key,c.objective_id
      FROM workshop_platform.completions c
      JOIN population p ON p.id=c.user_id
      JOIN workshop_platform.objectives o USING(workshop_key,objective_id)
      JOIN workshop_platform.exercises e ON e.workshop_key=o.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${ENABLED_OBJECTIVE}
    ), completion_by_student AS (
      SELECT user_id,workshop_key,count(*)::integer AS completed
      FROM eligible_completions GROUP BY user_id,workshop_key
    ), time_by_student AS (
      SELECT t.user_id,${LOGICAL_WORKSHOP_KEY('t.workshop_key')} AS workshop_key,
        sum(t.duration_seconds)::bigint AS seconds,
        count(*)::integer AS time_count,
        max(t.last_heartbeat) AS last_activity
      FROM workshop_platform.time_tracking t
      JOIN population p ON p.id=t.user_id
      JOIN workshop_platform.exercises e ON e.workshop_key=t.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${liveTimeCondition}
      GROUP BY t.user_id,${LOGICAL_WORKSHOP_KEY('t.workshop_key')}
    ), activity_by_student AS (
      SELECT a.user_id,${LOGICAL_WORKSHOP_KEY('a.workshop_key')} AS workshop_key,
        sum(a.activity_count)::bigint AS activity_count,
        max(a.updated_at) AS last_activity
      FROM workshop_platform.activity_counters a
      JOIN population p ON p.id=a.user_id
      JOIN workshop_platform.exercises e ON e.workshop_key=a.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND a.activity_count>0
      GROUP BY a.user_id,${LOGICAL_WORKSHOP_KEY('a.workshop_key')}
    ), engagement AS (
      SELECT p.id AS user_id,c.workshop_key,COALESCE(done.completed,0)::integer AS completed,
        (COALESCE(done.completed,0)>0 OR COALESCE(spent.time_count,0)>0
          OR COALESCE(activity.activity_count,0)>0) AS started
      FROM population p CROSS JOIN catalog c
      LEFT JOIN completion_by_student done ON done.user_id=p.id AND done.workshop_key=c.workshop_key
      LEFT JOIN time_by_student spent ON spent.user_id=p.id AND spent.workshop_key=c.workshop_key
      LEFT JOIN activity_by_student activity ON activity.user_id=p.id AND activity.workshop_key=c.workshop_key
    )
    SELECT c.workshop_key,c.challenge_key,c.challenge_name,c.difficulty,c.enabled_objectives,
      count(s.user_id) FILTER(WHERE s.started)::integer AS students_started,
      count(s.user_id) FILTER(WHERE c.enabled_objectives>0 AND s.completed=c.enabled_objectives)::integer AS students_completed,
      COALESCE(sum(s.completed),0)::integer AS total_completions,
      (SELECT avg(t.seconds)/60.0 FROM time_by_student t WHERE t.workshop_key=c.workshop_key) AS avg_time_minutes
    FROM catalog c LEFT JOIN engagement s ON s.workshop_key=c.workshop_key
    GROUP BY c.workshop_key,c.challenge_key,c.challenge_name,c.difficulty,c.enabled_objectives,c.ordinal
    ORDER BY c.ordinal,c.challenge_key`,

  students: `/* admin-progress-analytics:students */
    WITH population AS (
      SELECT u.id,u.username,u.last_login FROM identity.users u WHERE ${POPULATION}
    ), catalog AS (
      SELECT ${LOGICAL_WORKSHOP_KEY('e.workshop_key')} AS workshop_key,
        count(o.objective_id)::integer AS enabled_objectives
      FROM workshop_platform.exercises e
      LEFT JOIN workshop_platform.objectives o ON o.workshop_key=e.workshop_key
        AND ${ENABLED_OBJECTIVE}
      WHERE ${VISIBLE_EXERCISE}
      GROUP BY ${LOGICAL_WORKSHOP_KEY('e.workshop_key')}
    ), eligible_completions AS (
      SELECT c.user_id,${LOGICAL_WORKSHOP_KEY('c.workshop_key')} AS workshop_key,
        c.objective_id,c.completed_at
      FROM workshop_platform.completions c
      JOIN population p ON p.id=c.user_id
      JOIN workshop_platform.objectives o USING(workshop_key,objective_id)
      JOIN workshop_platform.exercises e ON e.workshop_key=o.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${ENABLED_OBJECTIVE}
    ), completion_by_workshop AS (
      SELECT user_id,workshop_key,count(*)::integer AS completed
      FROM eligible_completions GROUP BY user_id,workshop_key
    ), time_by_workshop AS (
      SELECT t.user_id,${LOGICAL_WORKSHOP_KEY('t.workshop_key')} AS workshop_key,
        sum(t.duration_seconds)::bigint AS seconds,
        count(*)::integer AS time_count,
        max(t.last_heartbeat) AS last_activity
      FROM workshop_platform.time_tracking t
      JOIN population p ON p.id=t.user_id
      JOIN workshop_platform.exercises e ON e.workshop_key=t.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND ${liveTimeCondition}
      GROUP BY t.user_id,${LOGICAL_WORKSHOP_KEY('t.workshop_key')}
    ), activity_by_workshop AS (
      SELECT a.user_id,${LOGICAL_WORKSHOP_KEY('a.workshop_key')} AS workshop_key,
        sum(a.activity_count)::bigint AS activity_count,
        max(a.updated_at) AS last_activity
      FROM workshop_platform.activity_counters a
      JOIN population p ON p.id=a.user_id
      JOIN workshop_platform.exercises e ON e.workshop_key=a.workshop_key
      WHERE ${VISIBLE_EXERCISE} AND a.activity_count>0
      GROUP BY a.user_id,${LOGICAL_WORKSHOP_KEY('a.workshop_key')}
    ), in_progress AS (
      SELECT p.id AS user_id,c.workshop_key
      FROM population p CROSS JOIN catalog c
      LEFT JOIN completion_by_workshop done ON done.user_id=p.id AND done.workshop_key=c.workshop_key
      LEFT JOIN time_by_workshop spent ON spent.user_id=p.id AND spent.workshop_key=c.workshop_key
      LEFT JOIN activity_by_workshop activity ON activity.user_id=p.id AND activity.workshop_key=c.workshop_key
      WHERE COALESCE(done.completed,0)<c.enabled_objectives
        AND (COALESCE(done.completed,0)>0 OR COALESCE(spent.time_count,0)>0
          OR COALESCE(activity.activity_count,0)>0)
    )
    SELECT p.id,p.username,p.last_login,
      (SELECT count(*)::integer FROM eligible_completions done WHERE done.user_id=p.id) AS objectives_completed,
      (SELECT count(*)::integer FROM in_progress active WHERE active.user_id=p.id) AS workshops_in_progress,
      GREATEST(
        (SELECT max(done.completed_at) FROM eligible_completions done WHERE done.user_id=p.id),
        (SELECT max(spent.last_activity) FROM time_by_workshop spent WHERE spent.user_id=p.id),
        (SELECT max(activity.last_activity) FROM activity_by_workshop activity WHERE activity.user_id=p.id)
      ) AS last_activity,
      COALESCE((SELECT sum(spent.seconds)::bigint FROM time_by_workshop spent WHERE spent.user_id=p.id),0)::bigint AS total_time_seconds
    FROM population p ORDER BY p.id`,

  timeline: `/* admin-progress-analytics:timeline */
    WITH population AS (
      SELECT u.id FROM identity.users u WHERE ${POPULATION}
    )
    SELECT (c.completed_at AT TIME ZONE 'UTC')::date::text AS date,
      count(*)::integer AS completions,count(DISTINCT c.user_id)::integer AS active_students
    FROM workshop_platform.completions c
    JOIN population p ON p.id=c.user_id
    JOIN workshop_platform.objectives o USING(workshop_key,objective_id)
    JOIN workshop_platform.exercises e ON e.workshop_key=o.workshop_key
    WHERE ${VISIBLE_EXERCISE} AND ${ENABLED_OBJECTIVE}
      AND c.completed_at BETWEEN ${UTC_30_DAY_START} AND ${SNAPSHOT_NOW}
    GROUP BY (c.completed_at AT TIME ZONE 'UTC')::date ORDER BY date DESC`,

  recentActivity: `/* admin-progress-analytics:recent-activity */
    SELECT l.action_type,l.action_details,l.timestamp,l.success,u.username
    FROM identity.activity_logs l JOIN identity.users u ON u.id=l.user_id
    WHERE ${POPULATION}
      AND l.action_type IN ('user_login','login','login_success','login_failed','challenge_complete')
    ORDER BY l.timestamp DESC,l.id DESC LIMIT 10`,
  });
}
const SQL = buildSql();

function number(value) {
  const result = Number(value ?? 0);
  return Number.isFinite(result) ? result : 0;
}
function rounded(value, places = 0) {
  const scale = 10 ** places;
  return Math.round(number(value) * scale) / scale;
}
function activityDescription(row) {
  let details = row.action_details;
  if (typeof details === 'string') {
    try { details = JSON.parse(details); } catch { details = null; }
  }
  return details && typeof details === 'object'
    ? details.action_description || details.message || row.action_type
    : row.action_type;
}
function activityMillis(value) {
  if (!value) return Number.NEGATIVE_INFINITY;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.NEGATIVE_INFINITY;
}

function projectSnapshot({ overview = {}, challenges = [], students = [], timeline = [], recentActivity = [] } = {}) {
  const totalStudents = number(overview.total_students);
  const totalEnabledObjectives = number(overview.total_enabled_objectives);
  const totalObjectiveCompletions = number(overview.total_objective_completions);
  const studentProgress = students.map(row => {
    const objectivesCompleted = number(row.objectives_completed);
    return {
      id: number(row.id), username: row.username, lastLogin: row.last_login || null,
      objectivesCompleted, totalEnabledObjectives,
      completionPercentage: totalEnabledObjectives ? rounded(100 * objectivesCompleted / totalEnabledObjectives) : 0,
      workshopsInProgress: number(row.workshops_in_progress), lastActivity: row.last_activity || null,
      totalTimeMinutes: rounded(number(row.total_time_seconds) / 60, 1),
    };
  });
  const challengeStats = challenges.map(row => {
    const studentsStarted = number(row.students_started);
    const studentsCompleted = number(row.students_completed);
    return {
      challengeKey: row.challenge_key, challengeName: row.challenge_name, difficulty: row.difficulty,
      enabledObjectives: number(row.enabled_objectives), studentsStarted, studentsCompleted,
      completionRate: studentsStarted ? rounded(100 * studentsCompleted / studentsStarted) : 0,
      avgTimeMinutes: rounded(row.avg_time_minutes, 1),
    };
  });
  const topStudents = studentProgress.filter(row => row.objectivesCompleted > 0)
    .sort((left, right) => right.objectivesCompleted - left.objectivesCompleted
      || (activityMillis(right.lastActivity) - activityMillis(left.lastActivity)) || left.id - right.id)
    .slice(0, 5);
  const difficulties = new Map();
  for (const row of challenges) {
    const difficulty = row.difficulty;
    const current = difficulties.get(difficulty) || { totalChallenges: 0, totalObjectives: 0, completed: 0, completionRate: 0 };
    current.totalChallenges += 1;
    current.totalObjectives += number(row.enabled_objectives);
    current.completed += number(row.total_completions);
    difficulties.set(difficulty, current);
  }
  const difficultyBreakdown = Object.fromEntries(difficulties);
  for (const current of Object.values(difficultyBreakdown)) {
    const denominator = totalStudents * current.totalObjectives;
    current.completionRate = denominator ? rounded(100 * current.completed / denominator) : 0;
  }
  return {
    overview: {
      totalStudents, activeStudents: number(overview.active_students), totalEnabledObjectives,
      totalObjectiveCompletions, completionsThisWeek: number(overview.completions_this_week),
      avgSessionMinutes: rounded(overview.avg_session_minutes, 1),
      platformCompletionRate: totalStudents && totalEnabledObjectives
        ? rounded(100 * totalObjectiveCompletions / (totalStudents * totalEnabledObjectives)) : 0,
    },
    platformStatistics: {
      registeredToday: number(overview.registered_today),
      registeredThisWeek: number(overview.registered_this_week),
      completionsToday: number(overview.completions_today),
      completionsThisWeek: number(overview.completions_this_week),
      totalAttempts: number(overview.total_evaluation_attempts),
      calendarTimeZone: 'UTC',
      attemptDefinition: 'Persisted canonical objective evaluations for active students and currently visible/enabled objectives; includes pending/unavailable, one per evaluation ID, not provider retries or audit events.',
      averageCompletionTime: null,
      averageCompletionTimeStatus: 'unavailable_no_objective_duration_measurement',
    },
    challengeStats,
    studentProgress,
    topStudents,
    progressOverTime: timeline.map(row => ({ date: row.date, completions: number(row.completions), activeStudents: number(row.active_students) })),
    difficultyBreakdown,
    recentActivity: recentActivity.map(row => ({ username: row.username, actionType: row.action_type,
      description: activityDescription(row), timestamp: row.timestamp, success: row.success })),
  };
}

function createAdminProgressAnalyticsRepository(pool) {
  if (!pool?.connect || !pool?.query) throw new TypeError('PostgreSQL pool is required');
  return Object.freeze({
    getSnapshot: () => consistentRead(pool, async client => {
      const readiness = (await client.query(INSTANCE_READINESS_SQL)).rows[0] || {};
      const sql = readiness.history && readiness.launch_scope && readiness.generation_scope
        ? SQL : buildSql('true');
      const overview = (await client.query(sql.overview)).rows[0] || {};
      const challenges = (await client.query(sql.challenges)).rows;
      const students = (await client.query(sql.students)).rows;
      const timeline = (await client.query(sql.timeline)).rows;
      const recentActivity = (await client.query(sql.recentActivity)).rows;
      return projectSnapshot({ overview, challenges, students, timeline, recentActivity });
    }),
  });
}

module.exports = { createAdminProgressAnalyticsRepository, projectSnapshot,
  _internals: { SQL, LIVE_TIME, INSTANCE_READINESS_SQL, buildSql } };

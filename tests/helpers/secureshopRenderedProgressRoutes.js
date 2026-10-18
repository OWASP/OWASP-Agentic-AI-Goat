'use strict';
// Owned browser qualification: actual catalog/progress/revision repositories.
// Platform login remains the surrounding harness's explicit owned session.
function mountRenderedProgressRoutes({app,pool,authenticateToken}) {
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(pool);
  const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(pool);
  const revisions=require('../../server/database/postgres/workshopRevisionRepository').createWorkshopRevisionStore(pool);
  app.get('/api/workshop/config/snapshot',authenticateToken,async(req,res)=>res.json(await config.getSnapshot()));
  app.get('/api/workshop/config/revision',authenticateToken,async(req,res)=>res.json({revision:await config.getRevision()}));
  app.use('/api/changes',require('../../server/routes/changeRevisions').createChangeRevisionsRouter({store:revisions,authenticateToken}));
  const handlers=require('../../server/routes/workshopProgressHandlers').createWorkshopProgressHandlers({
    progressService:progress, getActiveDays:async id=>Number((await pool.query(
      "SELECT count(DISTINCT (timestamp AT TIME ZONE 'UTC')::date) AS count FROM identity.activity_logs WHERE user_id=$1",[id])).rows[0].count) });
  app.get('/api/workshop/challenges',authenticateToken,handlers.getChallenges);
  app.get('/api/workshop/progress',authenticateToken,handlers.getProgress);
  app.get('/api/workshop/student/stats',authenticateToken,handlers.getStudentStats);
  app.get('/api/workshop/time/summary',authenticateToken,async(req,res)=>res.json({
    summary:Object.fromEntries((await progress.getVisibleUserProgress(req.user.id)).map(row=>[row.workshopKey,row.timeSpentSeconds])) }));
}
module.exports={mountRenderedProgressRoutes};

'use strict';
const { projectWorkshopChallenges } = require('../services/workshopChallengeProjection');
function createWorkshopProgressHandlers({ progressService, getActiveDays } = {}) {
  const loadCanonicalChallenges = async userId => projectWorkshopChallenges(
    await progressService.getVisibleUserProgress(userId)
  );

  return {
    getStudentStats: async (req, res) => {
      const userId = req.user?.id;
      if (!userId) return res.status(401).json({ error: 'Authentication required' });
      try {
        const [challenges, activeDays] = await Promise.all([
          loadCanonicalChallenges(userId),
          getActiveDays(userId),
        ]);
        return res.json({
          success: true,
          completedChallenges: challenges.filter((challenge) => challenge.status === 'completed').length,
          totalTime: challenges.reduce((sum, challenge) => sum + challenge.timeSpentSeconds, 0),
          streak: activeDays,
          totalObjectives: challenges.reduce((sum, challenge) => sum + challenge.objectiveCount, 0),
          completedObjectives: challenges.reduce((sum, challenge) => sum + challenge.completedObjectiveCount, 0),
          activeWorkshops: challenges.filter((challenge) => challenge.completedObjectiveCount > 0).length,
        });
      } catch (error) {
        console.error('Error fetching canonical student stats:', error);
        return res.status(500).json({ error: 'Failed to fetch student stats' });
      }
    },
    getProgress: async (req, res) => {
      const userId = req.user?.id;
      if (!userId) return res.status(401).json({ error: 'Authentication required' });
      try {
        return res.json({ challenges: await loadCanonicalChallenges(userId) });
      } catch (error) {
        console.error('Error fetching canonical workshop progress:', error);
        return res.status(500).json({ error: 'Failed to fetch workshop progress' });
      }
    },
    getChallenges: async (req, res) => {
      const userId = req.user?.id;
      if (!userId) return res.status(401).json({ error: 'Authentication required' });
      try {
        const challenges = await loadCanonicalChallenges(userId);
        if (challenges.length === 0) {
          return res.json({
            success: true,
            challenges: [],
            message: 'No challenges are currently available. Contact your instructor.'
          });
        }
        console.log(`[Challenge Visibility] Student ${userId} sees ${challenges.length} visible challenges`);
        return res.json({ success: true, challenges });
      } catch (error) {
        console.error('Error fetching canonical workshop challenges:', error);
        return res.status(500).json({ error: 'Failed to fetch challenges' });
      }
    },
  };
}

module.exports = { createWorkshopProgressHandlers };

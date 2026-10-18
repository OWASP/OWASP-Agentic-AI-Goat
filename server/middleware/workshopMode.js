const store = require('../database/legacyChallengeStore');

// Middleware to check if a vulnerability is enabled in workshop mode
const checkVulnerabilityAccess = (vulnerabilityKey) => {
  return (req, res, next) => {
    store.getVulnerabilitySetting(
      vulnerabilityKey,
      (err, row) => {
        if (err) {
          return res.status(503).json({
            error: 'Vulnerability Settings Unavailable',
            message: 'Exercise availability could not be verified. Please retry.',
            vulnerability: vulnerabilityKey,
            workshopMode: true
          });
        }
        
        // Availability is platform policy, not an intentional teaching sink.
        // Only explicit database enablement can admit the vulnerable handler.
        if (!row || (row.enabled !== 1 && row.enabled !== true)) {
          return res.status(403).json({
            error: 'Vulnerability Access Disabled',
            message: `The ${vulnerabilityKey} vulnerability is currently disabled by the workshop administrator.`,
            vulnerability: vulnerabilityKey,
            workshopMode: true
          });
        }
        
        next();
      }
    );
  };
};

// Get all vulnerability settings
const getVulnerabilitySettings = () => {
  return new Promise((resolve, reject) => {
    store.listVulnerabilitySettings( (err, rows) => {
      if (err) {
        reject(err);
      } else {
        const settings = {};
        rows.forEach(row => {
          settings[row.vulnerability_key] = (row.enabled === 1 || row.enabled === true);
        });
        resolve(settings);
      }
    });
  });
};

module.exports = {
  checkVulnerabilityAccess,
  getVulnerabilitySettings
};

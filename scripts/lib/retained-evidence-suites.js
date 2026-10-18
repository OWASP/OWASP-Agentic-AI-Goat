'use strict';
const retainedEvidenceSuites=Object.freeze(['secureshopMailReplyAuthorityCalibration.test.js','secureshopMailHeaderJudgeCases.test.js','dpiPracticeRetainedReplay.test.js']);
function isDefaultUnitSuite(name,serverRequired){return name.endsWith('.test.js')&&!serverRequired.has(name)&&!retainedEvidenceSuites.includes(name);}
module.exports={retainedEvidenceSuites,isDefaultUnitSuite};

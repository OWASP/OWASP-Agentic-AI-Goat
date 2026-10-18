'use strict';
// Closed traversal profile of the existing owned two-store entry; no new supervisor.
const shared=require('./finflowPolicyMain');
module.exports={admit:env=>shared.admit(env,'traversal'),run:()=>shared.run('traversal')};
if(require.main===module)module.exports.run().then(result=>{if(result.status!=='passed')process.exitCode=1;}).catch(()=>{process.stderr.write('FINFLOW_TRAVERSAL_FAILED\n');process.exitCode=1;});

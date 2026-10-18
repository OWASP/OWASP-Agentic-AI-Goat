'use strict';
// Runs one canonical initializer pass in a fresh owned Node process. Keeping it
// separate is required because PostgreSQL pool shutdown is process-global.
async function main(input){
 const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
 const {privateJson,runRetainedOwnershipInitializer}=require('./populated16-rehearsal.cjs');
 const value=privateJson(input).value,{installation,home,environment}=value;
 assert(path.isAbsolute(installation)&&path.isAbsolute(home)&&environment&&Object.getPrototypeOf(environment)===Object.prototype);
 assert.equal(fs.realpathSync(process.cwd()),installation);assert.equal(path.dirname(input),installation);assert.equal(process.env.HOME,home);
 await runRetainedOwnershipInitializer({environment});
}
if(require.main===module)main(process.argv[2]).catch(()=>{process.stderr.write('POPULATED_RETAINED_INITIALIZER_FAILED\n');process.exitCode=1;});
module.exports={main};

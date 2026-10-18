'use strict';

const USAGE = 'Usage: node scripts/admin/reset-auth-defaults.js --username <username> --password-stdin < /path/to/private-password-file';
const MAX_INPUT_BYTES = 512;

function parseArguments(args) {
  if (args.length !== 3 || !args.includes('--password-stdin')) throw new Error(USAGE);
  const usernameIndex=args.indexOf('--username');
  if(usernameIndex<0 || usernameIndex+1>=args.length || args[usernameIndex+1].startsWith('--')) throw new Error(USAGE);
  const username=args[usernameIndex+1];
  if(new Set(args).size!==3)throw new Error(USAGE);
  return {username};
}

async function readPassword(input) {
  if(input.isTTY)throw new Error('Password stdin must be piped; interactive echo is not supported');
  const chunks=[];let bytes=0;
  for await(const chunk of input){
    const value=Buffer.isBuffer(chunk)?chunk:Buffer.from(String(chunk));bytes+=value.length;
    if(bytes>MAX_INPUT_BYTES)throw new Error('Password input is too large');
    chunks.push(value);
  }
  let password=Buffer.concat(chunks).toString('utf8');
  if(password.endsWith('\n'))password=password.slice(0,-1);
  if(password.endsWith('\r'))password=password.slice(0,-1);
  if(!password || password.includes('\n') || password.includes('\r') || password.includes('\0'))
    throw new Error('Password stdin must contain exactly one nonempty line');
  return password;
}

async function loadProductionDependencies() {
  require('dotenv').config({path:require('node:path').resolve(__dirname,'../../.env'),quiet:true});
  const {resolveApplicationDatabaseEngine}=require('../../server/services/applicationDatabaseEngine');
  resolveApplicationDatabaseEngine({env:process.env});
  const {createPool,verifyServer}=require('../../server/database/postgres');
  const pool=createPool(process.env,'IDENTITY_DATABASE_URL');
  return {pool,verifyServer,repository:require('../../server/database/postgres/identityRepository').createIdentityRepository(pool),
    validateUsername:require('../../server/services/authValidation').validateUsername,
    validatePassword:require('../../server/services/authValidation').validatePassword,
    hashPassword:require('../../server/services/authValidation').secureHashPassword};
}

async function recoverAccount({username,password},dependencies) {
  const checkedUsername=dependencies.validateUsername(username);
  if(!checkedUsername.valid)throw new Error(checkedUsername.error);
  const checkedPassword=dependencies.validatePassword(password);
  if(!checkedPassword.valid)throw new Error(checkedPassword.error);
  const passwordHash=await dependencies.hashPassword(password);
  return dependencies.repository.recoverAccount(checkedUsername.sanitized,passwordHash);
}

async function main(args=process.argv.slice(2),io={input:process.stdin,output:process.stdout},loadDependencies=loadProductionDependencies) {
  if(args.length===1 && ['--help','-h'].includes(args[0])){io.output.write(`${USAGE}\n`);return null;}
  const selection=parseArguments(args);
  const password=await readPassword(io.input);
  const dependencies=await loadDependencies();
  try {
    await dependencies.verifyServer(dependencies.pool);
    const result=await recoverAccount({...selection,password},dependencies);
    io.output.write(`Recovered one account and revoked ${result.sessionsRevoked} active session(s). Roles, activation, permissions, profiles, and learner data were unchanged.\n`);
    return result;
  } finally {await dependencies.pool.end();}
}

if(require.main===module)main().catch(error=>{
  const expected=new Set([USAGE,'Password stdin must be piped; interactive echo is not supported',
    'Password input is too large','Password stdin must contain exactly one nonempty line']);
  console.error(expected.has(error.message)?error.message:
    `Account recovery failed (${error.code||'validation_configuration_or_database_error'}).`);
  process.exitCode=1;
});

module.exports={USAGE,parseArguments,readPassword,recoverAccount,loadProductionDependencies,main};

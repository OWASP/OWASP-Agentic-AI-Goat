'use strict';
// Trusted control-channel status only. Never call this on learner stdout.
const failure = code => Object.assign(new Error('Owned diagnostic execution unavailable'), {code});
function decodeDiagnosticStatus(bytes, exitCode) {
  if (exitCode !== 0) throw failure('SYSTEM_DIAGNOSTIC_HELPER_FAILED');
  const match = /^D1 (-1|0|[1-9][0-9]{0,2}) (0|[1-9][0-9]?) drained\n$/.exec(bytes.toString('ascii'));
  if (!match || !Buffer.from(bytes.toString('ascii'),'ascii').equals(bytes)) throw failure('SYSTEM_DIAGNOSTIC_STATUS_INVALID');
  const code=Number(match[1]), signal=Number(match[2]);
  if (code>255 || signal>64 || (code===-1)!==(signal>0)) throw failure('SYSTEM_DIAGNOSTIC_STATUS_INVALID');
  return {exitCode:code===-1?null:code,signal:signal||null,drained:true};
}
module.exports={decodeDiagnosticStatus};

'use strict';

function allowedDatabaseConnect(args, { host, port }) {
  let values = args;
  if (Array.isArray(values[0])) values = values[0]; // Node's normalized connect arguments
  const first = values[0];
  if (first && typeof first === 'object') {
    return (first.path === undefined || first.path === null) && first.host === host && String(first.port) === String(port);
  }
  if (typeof first !== 'number' && !(typeof first === 'string' && /^\d+$/.test(first))) return false;
  return values[1] === host && String(first) === String(port);
}

// Configuration is supplied by the owned launcher, never inferred from ambient env.
function validateNetworkConfiguration(database, configuration = { version: 1, services: [] }) {
  const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === keys.sort().join(',');
  const endpoint = value => value.host === '127.0.0.1'
    && /^(?:[1-9][0-9]*)$/.test(String(value.port)) && Number(value.port) <= 65535;
  if (!exact(database, ['host', 'port']) || !endpoint(database)
      || !exact(configuration, ['version', 'services']) || configuration.version !== 1
      || !Array.isArray(configuration.services) || configuration.services.length > 10) {
    throw Error('Invalid owned network configuration');
  }
  const ports = new Set([Number(database.port)]), names = new Set();
  const services = configuration.services.map(service => {
    if (!exact(service, ['name', 'host', 'port']) || !endpoint(service)
        || !/^(agent_host|model|fixture_[a-z][a-z0-9_]{0,31})$/.test(service.name)
        || names.has(service.name) || ports.has(Number(service.port))) throw Error('Invalid owned service endpoint');
    names.add(service.name);ports.add(Number(service.port));
    return Object.freeze({ name: service.name, host: service.host, port: Number(service.port) });
  });
  return Object.freeze({ version: 1, database: Object.freeze({ host: database.host, port: Number(database.port) }),
    services: Object.freeze(services) });
}

function networkGuardSource(endpoint, configuration) {
  const policy = validateNetworkConfiguration(endpoint, configuration);
  return `'use strict';const allowed=${allowedDatabaseConnect.toString()};
const policy=${JSON.stringify(policy)};const net=require('node:net');const original=net.Socket.prototype.connect;
net.Socket.prototype.connect=function(...args){if(![policy.database,...policy.services].some(endpoint=>allowed(args,endpoint)))throw Error('QUALIFICATION_NETWORK_BLOCKED');return original.apply(this,args)};
const originalFetch=global.fetch;
global.fetch=async(input,options={})=>{
 if(options===null||typeof options!=='object'||'dispatcher' in options)throw Error('QUALIFICATION_PROVIDER_BLOCKED');
 const supported=typeof input==='string'||input instanceof URL||(typeof Request==='function'&&input instanceof Request);
 if(!supported)throw Error('QUALIFICATION_PROVIDER_BLOCKED');
 let url;const raw=typeof input==='string'?input:input instanceof URL?input.href:input.url;try{url=new URL(raw)}catch{throw Error('QUALIFICATION_PROVIDER_BLOCKED')}
 if(typeof raw!=='string'||!raw.startsWith('http://127.0.0.1:'+url.port+'/'))throw Error('QUALIFICATION_PROVIDER_BLOCKED');
 if(url.protocol!=='http:'||url.username||url.password||url.hash||!policy.services.some(endpoint=>url.hostname===endpoint.host&&Number(url.port||80)===endpoint.port))throw Error('QUALIFICATION_PROVIDER_BLOCKED');
 return originalFetch(input,{...options,redirect:'error'});
};\n`;
}

function waitForChild(child, { timeoutMs = 30000, signal } = {}) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve, reject) => {
    const done = (error, code) => {
      clearTimeout(timer);child.removeListener('exit', onExit);child.removeListener('error', onError);
      signal?.removeEventListener('abort', onAbort);
      error ? reject(error) : resolve(code);
    };
    const onExit = code => done(null, code);
    const onError = error => done(error);
    const onAbort = () => done(signal.reason || Error('Child wait aborted'));
    const timer = setTimeout(() => done(Error('Child exit deadline')), timeoutMs);
    child.once('exit', onExit);child.once('error', onError);signal?.addEventListener('abort', onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function createOwnedChildren(spawn) {
  const active = new Set();
  function launch(command, args, options) {
    // Same process group: the outer verified launcher owns all descendants.
    const child = spawn(command, args, { ...options, detached: false });
    active.add(child);
    child.once('error', () => {}); // prevent unhandled spawn error before wait attaches
    return child;
  }
  async function stop(child) {
    if (!active.has(child)) return;
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      try { await waitForChild(child, { timeoutMs: 3000 }); }
      catch {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await waitForChild(child, { timeoutMs: 3000 });
      }
    }
    active.delete(child);
  }
  async function cleanup() {
    const results = await Promise.allSettled([...active].map(stop));
    if (results.some(result => result.status === 'rejected')) throw Error('Owned child cleanup failed');
  }
  return { launch, cleanup, stop };
}
module.exports = { validateNetworkConfiguration, allowedDatabaseConnect, networkGuardSource, waitForChild, createOwnedChildren };

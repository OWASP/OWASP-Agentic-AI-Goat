'use strict';
// Installed only in the dedicated DB-phase process, before setup helper imports.
// Tracks direct subprocesses and their declared POSIX process groups, not remote
// Docker services or arbitrary reparented/setsid descendants.
function installSetupChildOwnership({ childProcess = require('node:child_process'), signal, notify = () => {} } = {}) {
  const original = {}, children = new Map();
  const absent = item => {
    if (!item.child.pid) return item.closedFlag;
    if (!item.grouped) return item.closedFlag;
    try { process.kill(-item.child.pid,0); return false; } catch (error) { return error.code === 'ESRCH'; }
  };
  const retire = item => {
    if (!item.closedFlag || !absent(item)) return false;
    clearTimeout(item.monitor); children.delete(item.child);
    if (item.child.pid) notify({type:'child-closed',pid:item.child.pid,id:item.id});
    return true;
  };
  let stopped = false;
  const kill = (child, grouped, name) => {
    try { if (grouped && child.pid) process.kill(-child.pid, name); else child.kill(name); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  };
  function track(child, grouped) {
    if (!child || children.has(child)) return child;
    let done;
    const closed = new Promise(resolve => { done = resolve; });
    const item = { child, grouped, closed, closedFlag: false, id: require('node:crypto').randomUUID() };
    children.set(child, item);
    child.once('spawn', () => { notify({ type: 'child', pid: child.pid, grouped, id:item.id }); if (stopped) kill(child, grouped, 'SIGTERM'); });
    child.once('close', () => { item.closedFlag = true; done(); const check=()=>{if(!retire(item))item.monitor=setTimeout(check,20);};check(); });
    child.once('error', () => { if (!child.pid) { item.closedFlag = true; done(); retire(item); } });
    return child;
  }
  for (const name of ['spawn', 'execFile', 'fork']) {
    original[name] = childProcess[name];
    childProcess[name] = function(...args) {
      if (stopped) throw Object.assign(Error('Setup cancelled'), { code: 'SETUP_CANCELLED' });
      const options = name === 'spawn' ? args[2] : args.find((arg, index) => index > 0 && arg && typeof arg === 'object' && !Array.isArray(arg));
      return track(original[name].apply(this, args), process.platform !== 'win32' && options?.detached === true);
    };
    // promisify(execFile) depends on its custom symbol, whose original bypasses
    // our wrapper. Supply a tracked equivalent preserving stdout/stderr shape.
    if (name === 'execFile') childProcess[name][require('node:util').promisify.custom] = (...args) => {
      let child;
      const promise = new Promise((resolve, reject) => {
        child = childProcess.execFile(...args, (error, stdout, stderr) => {
          if (error) { error.stdout = stdout; error.stderr = stderr; reject(error); }
          else resolve({ stdout, stderr });
        });
      });
      promise.child = child;
      return promise;
    };
  }
  function stop() { stopped = true; for (const item of children.values()) if (!retire(item) && item.child.pid) kill(item.child, item.grouped, 'SIGTERM'); }
  signal?.addEventListener('abort', stop, { once: true });
  if (signal?.aborted) stop();
  return {
    async drain({ timeoutMs = 10000 } = {}) {
      const end = Date.now() + timeoutMs;
      // Rejected runner promises are not process termination. Join streams and
      // process groups even when a helper already reported failure.
      const pending = () => {
        for (const item of children.values()) retire(item);
        return children.size > 0;
      };
      while (pending()) {
        if (stopped) for (const item of children.values()) if (!retire(item) && item.child.pid) kill(item.child, item.grouped, 'SIGKILL');
        if (Date.now() >= end) throw Object.assign(Error('Owned setup children not drained'), { code: 'SETUP_CHILDREN_UNDRAINED' });
        await new Promise(resolve => setTimeout(resolve, 20));
      }
    },
    stop,
    restore() { signal?.removeEventListener('abort', stop); for (const name of Object.keys(original)) childProcess[name] = original[name]; },
  };
}
module.exports = { installSetupChildOwnership };

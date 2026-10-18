'use strict';

const { performance } = require('node:perf_hooks');

/**
 * Account for an HTTP request when its response finishes or closes early.
 *
 * The fourth recordMetrics argument is additive: existing monitors that accept
 * only (endpoint, durationMs, isError) keep working, while newer monitors can
 * retain the actual status and distinguish an aborted transport.
 */
function createTrackRequestCompletion(monitor, { now = () => performance.now() } = {}) {
  if (!monitor || typeof monitor.recordMetrics !== 'function' ||
      !monitor.systemStats || typeof now !== 'function') {
    throw new TypeError('monitor.recordMetrics, monitor.systemStats and a clock are required');
  }

  return function trackRequestCompletion(req, res, next) {
    const startedAt = now();
    const endpoint = req.path;
    let completed = false;

    monitor.systemStats.activeConnections += 1;

    const complete = (aborted) => {
      if (completed) return;
      completed = true;
      res.off('finish', onFinish);
      res.off('close', onClose);
      monitor.systemStats.activeConnections -= 1;

      const statusCode = res.statusCode;
      const durationMs = Math.max(0, now() - startedAt);
      monitor.recordMetrics(endpoint, durationMs, aborted || statusCode >= 400, {
        statusCode,
        aborted,
      });
    };
    const onFinish = () => complete(false);
    const onClose = () => complete(!res.writableFinished);

    res.once('finish', onFinish);
    res.once('close', onClose);
    next();
  };
}

module.exports = { createTrackRequestCompletion };

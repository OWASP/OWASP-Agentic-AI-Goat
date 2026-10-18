class ChatStream {
  constructor(res) {
    this.res = res;
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      'connection': 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write(': stream open\n\n');
  }

  send(eventName, data) {
    if (this.res.destroyed || this.res.writableEnded) return;
    this.res.write(`event: ${eventName}\n`);
    this.res.write(`data: ${JSON.stringify(data)}\n\n`);
  }

  close() {
    try { this.res.end(); } catch {}
  }
}

/** Tie a queued graph turn to its HTTP connection, without releasing its lock
 * until the graph has settled. Already-started tool effects are not rolled back. */
async function runChatTurn(req, res, { sessionId, message, agentSession, supervisor, provider, pool, manifest, localTools }) {
  // Only server-supplied closures enter this handoff; never req.body/header data.
  const executors = localTools == null ? undefined : new Map(localTools instanceof Map ? localTools : Object.entries(localTools));
  const controller = new AbortController();
  const abort = () => controller.abort();
  const onClose = () => { if (!res.writableFinished) abort(); };
  req.once('aborted', abort);
  res.once('close', onClose);
  let stream;
  try {
    if (req.aborted || res.destroyed) abort();
    controller.signal.throwIfAborted();
    stream = new ChatStream(res);
    await agentSession.runExclusive(sessionId, () => {
      controller.signal.throwIfAborted();
      return supervisor.run(sessionId, message, {
        provider, pool, manifest, stream, signal: controller.signal,
        ...(executors ? { localTools: executors } : {}),
        callerRole: req.ssUser.role, callerId: req.ssUser.id,
      });
    });
  } catch (error) {
    if (!controller.signal.aborted && !stream) throw error;
    if (!controller.signal.aborted && stream) {
      try { stream.send('error', { message: error.message }); } catch {}
    }
  } finally {
    req.off('aborted', abort);
    res.off('close', onClose);
    stream?.close();
  }
}

module.exports = { ChatStream, runChatTurn };

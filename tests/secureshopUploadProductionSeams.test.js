'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {
  createHash
} = require('node:crypto');
const {
  createSecureShopUploadWriter
} = require('../server/services/secureshopUploadWriter');
const {
  createSecureShopUploadAssetReader
} = require('../server/services/secureshopUploadAssetReader');
const {
  normalizeAdmission,
  normalizeEffect
} = require('../server/services/secureshopBoundUploadReceipt');
const {
  uploadAdmission
} = require('../server/services/secureshopBoundUploadAdmission');
const id = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const digest = b => createHash('sha256').update(b).digest('hex');
const unavailableSvgAssessment = Object.freeze({
  async runAttempt() { throw Error('Unexpected SVG assessment'); },
  async readOutcome() { throw Error('Unexpected SVG assessment'); }
});
async function storage(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'v06-owned-')));
  t.after(() => fs.rm(root, {
    recursive: true,
    force: true
  }));
  return {
    root,
    environment: {
      SECURESHOP_UPLOAD_ROOT: root
    }
  };
}
function admission(bytes = Buffer.from('lesson')) {
  return normalizeAdmission({
    operationId: id(1),
    uploadRequestId: id(2),
    storageKey: id(3),
    scope: {
      targetId: id(4),
      launchId: id(5),
      scenarioId: id(6),
      generation: 1,
      platformOwnerId: 7,
      platformSessionId: 8,
      sceneId: id(9),
      sceneGeneration: 1,
      grantId: id(10),
      shopUserId: 11,
      personaSessionId: id(12),
      personaAuthorityVersion: '1',
      mode: 'vuln',
      modeGeneration: 0,
      modeStamp: 'a'.repeat(64)
    },
    request: {
      kind: 'avatar',
      scopeId: 11,
      originalFilename: 'lesson.html',
      declaredMime: 'text/html',
      public: false,
      byteCount: bytes.length,
      bodySha256: digest(bytes)
    }
  });
}
test('production writer invokes real teaching tool in exclusive operation directory and preserves active extension bytes', async t => {
  const {
      root,
      environment
    } = await storage(t),
    writer = createSecureShopUploadWriter({
      environment
    });
  for (const [i, ext] of ['php', 'html', 'js'].entries()) {
    const bytes = Buffer.from(`synthetic-${ext}`),
      storageKey = id(30 + i);
    const input = {
      operationId: id(20 + i),
      storageKey,
      shopUserId: 11,
      bytes,
      filename: `lesson.${ext}`,
      mime: 'text/html'
    };
    const result = await writer.writeAndReadBack(input);
    assert.equal(result.isTraversal, false);
    assert.equal(result.bodySha256, digest(bytes));
    assert.equal(result.baseVirtualPath, `operations/${storageKey}/avatars/11`);
    assert.deepEqual(await fs.readFile(path.join(root, result.storedVirtualPath)), bytes);
    await assert.rejects(writer.writeAndReadBack(input), {
      code: 'BOUND_UPLOAD_OUTCOME_UNCERTAIN'
    });
    assert.equal((await fs.readdir(path.dirname(path.join(root, result.storedVirtualPath)))).length, 1);
  }
});
test('production writer rejects traversal before effect and bounded reader rejects symlink and mutated bytes', async t => {
  const {
      root,
      environment
    } = await storage(t),
    writer = createSecureShopUploadWriter({
      environment
    }),
    bytes = Buffer.from('lesson');
  const input = {
    operationId: id(1),
    storageKey: id(3),
    shopUserId: 11,
    bytes,
    filename: 'lesson.html',
    mime: 'text/html'
  };
  await assert.rejects(writer.writeAndReadBack({
    ...input,
    filename: '....//escape.html'
  }), {
    code: 'INVALID_ARGUMENT'
  });
  const result = await writer.writeAndReadBack(input),
    reader = createSecureShopUploadAssetReader({
      environment
    });
  const receipt = {
    storedVirtualPath: result.storedVirtualPath,
    responseByteCount: bytes.length,
    responseSha256: digest(bytes)
  };
  const filename = path.join(root, result.storedVirtualPath);
  await fs.writeFile(filename, 'change');
  await assert.rejects(reader(receipt), /CHANGED/);
  await fs.unlink(filename);
  await fs.symlink(path.join(root, 'foreign'), filename);
  await assert.rejects(reader(receipt), /UNAVAILABLE/);
});
test('normalized admission adapter accepts real claim/lookup DTO and verifies retained digests', () => {
  const a = admission();
  assert.deepEqual(uploadAdmission({
    ...a,
    replayed: false
  }), a);
  assert.deepEqual(uploadAdmission(a), a);
  assert.throws(() => uploadAdmission({
    ...a,
    bindingSha256: 'f'.repeat(64)
  }), /digest changed/);
});
test('real application lost acknowledgement rereads immutable effect and never repeats sink', async t => {
  const {
      environment
    } = await storage(t),
    bytes = Buffer.from('lesson'),
    a = admission(bytes);
  const real = createSecureShopUploadWriter({
    environment
  });
  let calls = 0,
    effect = null;
  const app = require('../server/services/secureshopBoundUploadApplication').createSecureShopBoundUploadApplication({
    effects: {
      find: async () => effect
    },
    writer: {
      async writeAndReadBack(value) {
        calls++;
        return real.writeAndReadBack(value);
      }
    },
    journal: {
      async recordEffect(_a, value) {
        effect = normalizeEffect(value, a);
        throw Error('lost acknowledgement');
      }
    }
  });
  const input = {
    admission: a,
    file: {
      bytes,
      filename: 'lesson.html',
      mime: 'text/html'
    },
    mode: 'vuln',
    execution: {
      async check() {}
    },
    effectId: id(99)
  };
  assert.equal((await app.execute(input)).effect.outcome, 'completed');
  assert.equal((await app.execute(input)).effect.outcome, 'completed');
  assert.equal(calls, 1);
});
test('real application fixed denial has no directory and safe fixed png remains usable', async t => {
  const {
      root,
      environment
    } = await storage(t),
    bytes = Buffer.from('lesson'),
    a = admission(bytes);
  let calls = 0;
  const writer = createSecureShopUploadWriter({
    environment
  });
  const app = require('../server/services/secureshopBoundUploadApplication').createSecureShopBoundUploadApplication({
    effects: {
      find: async () => null
    },
    writer: {
      async writeAndReadBack(v) {
        calls++;
        return writer.writeAndReadBack(v);
      }
    },
    journal: {
      async recordEffect(_a, v) {
        return normalizeEffect(v, _a);
      }
    }
  });
  const input = {
    admission: a,
    file: {
      bytes,
      filename: 'lesson.html',
      mime: 'text/html'
    },
    mode: 'fixed',
    execution: {
      async check() {}
    },
    effectId: id(99)
  };
  assert.equal((await app.execute(input)).effect.outcome, 'denied');
  assert.equal(calls, 0);
  assert.deepEqual(await fs.readdir(root), []);
  const safe = normalizeAdmission({
    operationId: id(101),
    uploadRequestId: id(102),
    storageKey: id(103),
    scope: a.scope,
    request: {
      ...a.request,
      originalFilename: 'lesson.png',
      declaredMime: 'image/png'
    }
  });
  assert.equal((await app.execute({
    ...input,
    admission: safe,
    file: {
      bytes,
      filename: 'lesson.png',
      mime: 'image/png'
    },
    effectId: id(104)
  })).effect.outcome, 'completed');
  assert.equal(calls, 1);
});
test('effect reader accepts the repository claim DTO and rejects corrupted effect digest', async () => {
  const a = admission(),
    effect = normalizeEffect({
      effectId: id(99),
      outcome: 'denied',
      file: null,
      denialCode: 'EXTENSION_DENIED',
      quarantineRequired: false
    }, a);
  const row = {
    effect_id: effect.effectId,
    outcome: 'denied',
    storage_key: null,
    denial_code: effect.denialCode,
    quarantine_required: false,
    effect_sha256: Buffer.from(effect.effectSha256, 'hex')
  };
  const reader = require('../server/database/postgres/secureshopBoundUploadEffectReader').createSecureShopBoundUploadEffectReader({
    query: async () => ({
      rows: [row]
    })
  }, {
    checkCurrent: async () => {},
    assertSceneGrant: async () => {}
  });
  assert.equal((await reader.find({
    ...a,
    replayed: false
  })).outcome, 'denied');
  row.effect_sha256 = Buffer.alloc(32);
  await assert.rejects(reader.find(a), /CHANGED/);
});
test('production upload graph resolves trusted scene and completes real runner with physical attachment and immutable metadata', async t => {
  const {
      environment
    } = await storage(t),
    bytes = Buffer.from('lesson'),
    a = admission(bytes),
    scope = {
      launchId: a.scope.launchId,
      scenarioId: a.scope.scenarioId,
      generation: 1,
      platformOwnerId: 7,
      platformSessionId: 8
    };
  const persona = {
      id: 11,
      role: 'customer'
    },
    personaSession = {
      sessionId: id(12),
      authorityVersion: '1'
    },
    sessionId = id(51),
    requestId = id(52);
  const target = require('../server/services/secureshopSceneBinding').createSceneBinding({
    ...scope,
    targetId: id(4)
  }, {
    sceneId: id(9),
    sceneGeneration: 1,
    grantId: id(10),
    execution: scope,
    withLease: work => work()
  });
  const session = {
    id: sessionId,
    state: 'active',
    purpose: 'secureshop_avatar_upload',
    binding: {
      ...scope,
      shopUserId: 11,
      role: 'customer'
    }
  };
  const messages = [],
    trace = [];
  let modelCalls = 0,
    writes = 0,
    saved = null,
    claimed = null,
    effect = null,
    actorArgs = {};
  const conversationRepository = {
    getBoundSession: async () => session,
    getMessages: async () => messages,
    appendMessage: async (_s, _b, m) => messages.push(m),
    getTokens: async () => 0,
    addTokens: async () => {},
    appendTraces: async (_s, _b, rows) => trace.push(...rows)
  };
  const turnJournal = {
    async claim(input) {
      if (saved) {
        assert.equal(input.message, claimed);
        return {
          status: 'completed',
          result: saved
        };
      }
      claimed = input.message;
      return {
        status: 'claimed',
        claimId: id(60)
      };
    },
    async complete(input) {
      saved = input.result;
    },
    async markUncertain() {}
  };
  const uploadJournal = {
    async claim(raw) {
      return {
        ...normalizeAdmission(raw),
        replayed: false
      };
    },
    async recordEffect(raw, value) {
      effect = normalizeEffect(value, raw);
      return effect;
    }
  };
  const writer = createSecureShopUploadWriter({
    environment
  });
  const application = require('../server/services/secureshopBoundUploadApplication').createSecureShopBoundUploadApplication({
    effects: {
      find: async () => effect
    },
    journal: uploadJournal,
    writer: {
      async writeAndReadBack(value) {
        writes++;
        return writer.writeAndReadBack(value);
      }
    }
  });
  const runId = id(61),
    ownerKey = 'upload-controlled-owner';
  const coordinator = {
    async run(_sid, options, work) {
      const decision = await options.admit();
      if (decision.skip) return decision.value;
      return work({
        runId,
        ownerKey,
        generation: 1,
        durableGeneration: '1',
        check: async () => {},
        effect: async (_key, fn) => fn(),
        effectWithReceipt: async (key, fn) => ({
          value: await fn(),
          receipt: {
            version: 1,
            runId,
            ownerKey,
            generation: '1',
            effectKey: `${options.idempotencyKey}:${key}`,
            status: 'completed'
          }
        }),
        trace: async () => {}
      });
    }
  };
  const mode = {
    snapshot: {
      version: 1,
      featureId: 'uploads',
      policyVersion: 'owner-bound-avatar-extension-policy-v1',
      mode: 'vuln',
      generation: 0,
      modeStamp: 'a'.repeat(64)
    },
    assertCurrent: async () => {}
  };
  const {
    REGISTRY_SHA256
  } = require('../server/services/secureshopBoundAclRegistry');
  const graph = require('../server/services/secureshopBoundUploadGraph').createSecureShopBoundUploadGraph({
    launches: {
      assertCurrent: async () => {}
    },
    conversationRepository,
    journal: turnJournal,
    coordinator,
    provider: {
      async chat(input) {
        modelCalls++;
        assert.equal(input.closedToolCatalog, true);
        return {
          provider: 'ollama',
          model: 'controlled-actor',
          mocked: false,
          stop_reason: 'tool_use',
          tool_uses: [{
            id: 'upload-call',
            name: 'uploads.upload_avatar',
            args: actorArgs
          }]
        };
      },
      async finalResponse() {
        modelCalls++;
        return {
          provider: 'ollama',
          model: 'controlled-actor',
          mocked: false,
          responseMode: 'structured_final',
          stop_reason: 'end_turn',
          text: 'Attachment stored.'
        };
      }
    },
    uploadApplication: application,
    uploadJournal,
    personaAuthority: {
      capture: () => ({
        binding: {
          ...scope,
          personaId: 11,
          role: 'customer',
          ...personaSession
        },
        assertRemoteAdmission: async () => {},
        withPersonaEffect: async fn => fn()
      })
    },
    modeAuthority: {
      capture: async () => mode,
      assertToken: value => value
    },
    toolPolicyRepository: {
      async admitTool(input) {
        return {
          admissionId: id(62),
          runId: input.runId,
          invocationId: input.invocationId,
          toolKey: 'uploads.upload_avatar',
          policyVersion: '1',
          registrySha256: REGISTRY_SHA256,
          enforcement: true,
          allowed: true,
          action: 'dispatch',
          policyViolation: null
        };
      }
    },
    assetOrigin: 'http://127.0.0.2:9083',
    assetCapability: {
      mint: () => ({
        path: '/assets/controlled',
        expiresAt: Date.now() + 1000
      })
    },
    resolveTarget: async () => target,
    verifyEffect: async () => effect,
    assertUploadCurrent: async raw => assert.equal(raw.scope.targetId, target.targetId)
  });
  const input = {
    scope,
    persona,
    personaSession,
    sessionId,
    requestId,
    message: 'Upload my attached avatar',
    attachment: {
      bytes,
      filename: 'lesson.html',
      mime: 'text/html',
      public: false
    }
  };
  const result = await graph.run(input);
  assert.equal(result.text, 'Attachment stored.');
  assert.equal(result.taskMetadata.boundUpload.outcome, 'completed');
  assert.equal(writes, 1);
  assert.equal(modelCalls, 2);
  assert.equal(JSON.parse(claimed).attachment.bodySha256, digest(bytes));
  assert.equal(result.taskMetadata.boundUpload.graphEffect.runId, runId);
  assert.equal((await graph.run(input)).replayed, true);
  assert.equal(writes, 1);
  assert.equal(modelCalls, 2);
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(graph.run({
    ...input,
    signal: aborted.signal
  }));
  assert.equal(modelCalls, 2);
  saved = null;
  effect = null;
  mode.snapshot.mode = 'fixed';
  const denied = await graph.run({
    ...input,
    requestId: id(53)
  });
  assert.equal(denied.taskMetadata.boundUpload.outcome, 'denied');
  assert.equal(writes, 1);
  saved = null;
  effect = null;
  const safe = await graph.run({
    ...input,
    requestId: id(54),
    attachment: {
      ...input.attachment,
      filename: 'safe.png',
      mime: 'image/png'
    }
  });
  assert.equal(safe.taskMetadata.boundUpload.outcome, 'completed');
  assert.equal(writes, 2);
  saved = null;
  effect = null;
  actorArgs = {
    user_id: 999
  };
  await assert.rejects(graph.run({
    ...input,
    requestId: id(55)
  }));
  assert.equal(writes, 2);
});
test('actual bound upload route handlers latch preabort and suppress responses after awaited session cancellation', async () => {
  const {
    EventEmitter
  } = require('node:events');
  let calls = 0,
    sends = 0,
    release;
  const graph = {
    async createSession() {
      calls++;
      await new Promise(resolve => {
        release = resolve;
      });
      return {
        id: id(1)
      };
    },
    async run() {
      calls++;
    }
  };
  const router = require('../server/routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
    assessment: {async runAttempt(){throw Error('Unexpected assessment');},async readOutcome(){throw Error('Unexpected assessment');}},
    svgAssessment: unavailableSvgAssessment,
    launches: {
      resolveCapability: async () => {}
    },
    authenticatePersona: (_q, _s, n) => n(),
    graph,
    saved: {
      read: async () => {},
      asset: async () => {}
    }
  });
  const handler = pathname => router.stack.find(layer => layer.route?.path === pathname).route.stack.at(-1).handle;
  const request = () => Object.assign(new EventEmitter(), {
    ssLaunch: {},
    ssUser: {
      id: 11,
      role: 'customer'
    },
    ssPersonaSession: {
      sessionId: id(12),
      authorityVersion: '1'
    },
    query: {},
    body: {}
  });
  const response = () => Object.assign(new EventEmitter(), {
    status() {
      return this;
    },
    json() {
      sends++;
    }
  });
  for (const route of ['/agents/customer/avatar-upload/session', '/agents/customer/avatar-upload/run']) {
    const req = request(),
      res = response();
    req.aborted = true;
    await handler(route)(req, res);
  }
  assert.equal(calls, 0);
  assert.equal(sends, 0);
  const req = request(),
    res = response(),
    pending = handler('/agents/customer/avatar-upload/session')(req, res);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 1);
  req.emit('aborted');
  release();
  await pending;
  assert.equal(sends, 0);
});
test('application CORS rejects the asset origin before bound upload authority, model, effect or mint', async t => {
  const express=require('express'),http=require('node:http');
  const counters={launch:0,persona:0,model:0,effect:0,mint:0};
  const router=require('../server/routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
    launches:{async resolveCapability(){counters.launch++;return null;}},
    authenticatePersona(_req,_res,next){counters.persona++;next();},
    graph:{async createSession(){counters.model++;return{id:id(1)};},async run(){counters.model++;counters.effect++;}},
    saved:{async read(){},async asset(){counters.mint++;}},
    assessment:{async runAttempt(){throw Error('Unexpected assessment');},async readOutcome(){throw Error('Unexpected assessment');}},
    svgAssessment: unavailableSvgAssessment
  });
  const app=express();
  app.use(require('../server/middleware/applicationCors').createApplicationCors({secureShopOrigins:['http://localhost:3000','http://127.0.0.1:3000']}));
  app.use('/api/secureshop/agents',router);
  const server=http.createServer(app);
  t.after(()=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())));
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  const response=await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/agents/customer/avatar-upload/run`,{method:'POST',headers:{Origin:'http://[::1]:9083','x-dvaia-secureshop-launch':'x'.repeat(43)}});
  assert.equal(response.status,403);
  assert.deepEqual(await response.json(),{error:'Origin not allowed by SecureShop CORS policy'});
  assert.deepEqual(counters,{launch:0,persona:0,model:0,effect:0,mint:0});
});
test('saved operation GET projects immutable status without minting, serving, writing or Judge', async () => {
  const a = admission(),
    row = {
      operation_id: a.operationId,
      upload_request_id: a.uploadRequestId,
      storage_key: a.storageKey,
      target_id: a.scope.targetId,
      launch_id: a.scope.launchId,
      scenario_id: a.scope.scenarioId,
      generation: '1',
      platform_owner_id: 7,
      platform_session_id: 8,
      scene_id: a.scope.sceneId,
      scene_generation: '1',
      grant_id: a.scope.grantId,
      shop_user_id: 11,
      persona_session_id: a.scope.personaSessionId,
      persona_authority_version: '1',
      mode: 'vuln',
      mode_generation: '0',
      mode_stamp: Buffer.from(a.scope.modeStamp, 'hex'),
      kind: 'avatar',
      scope_id: 11,
      original_filename: 'lesson.html',
      declared_mime: 'text/html',
      is_public: false,
      byte_count: a.request.byteCount,
      body_sha256: Buffer.from(a.request.bodySha256, 'hex'),
      binding_sha256: Buffer.from(a.bindingSha256, 'hex'),
      request_sha256: Buffer.from(a.requestSha256, 'hex')
    };
  let minted = 0,
    checked = 0,
    duplicate = false,
    revoked = false;
  const queries = [];
  const saved = require('../server/services/secureshopBoundUploadSavedOperation').createSecureShopBoundUploadSavedOperation({
    pool: {
      query: async (sql, args) => {
        queries.push({
          sql,
          args
        });
        const allowed = [a.operationId, a.uploadRequestId].includes(args[0]) && args[4] === 7 && args[5] === 8;
        return {
          rows: allowed ? duplicate ? [row, row] : [row] : []
        };
      }
    },
    assertCurrent: async () => {
      checked++;
      if (revoked) throw Error('retired authority');
    },
    effects: {
      find: async () => null
    },
    capability: {
      mint() {
        minted++;
      }
    },
    assetOrigin: 'http://127.0.0.2:9083'
  });
  const out = await saved.read({
    scope: a.scope,
    persona: {
      id: 11,
      role: 'customer'
    },
    personaSession: {
      sessionId: a.scope.personaSessionId,
      authorityVersion: '1'
    },
    operationId: a.operationId
  });
  assert.deepEqual(Object.keys(out).sort(), ['byteCount', 'filename', 'operationId', 'status', 'uploadRequestId']);
  assert.equal(out.status, 'uncertain');
  assert.equal(minted, 0);
  assert.equal(checked, 2);
  const input = {
    scope: a.scope,
    persona: {
      id: 11,
      role: 'customer'
    },
    personaSession: {
      sessionId: a.scope.personaSessionId,
      authorityVersion: '1'
    },
    uploadRequestId: a.uploadRequestId
  };
  const recovered = await saved.read(input);
  assert.deepEqual(recovered, out);
  assert.match(queries.at(-1).sql, /WHERE a\.upload_request_id=\$1/);
  assert.equal(queries.at(-1).args[0], a.uploadRequestId);
  assert.equal(minted, 0);
  await assert.rejects(saved.read({
    ...input,
    uploadRequestId: id(404)
  }));
  await assert.rejects(saved.read({
    ...input,
    scope: {
      ...a.scope,
      platformOwnerId: 99
    }
  }));
  await assert.rejects(saved.read({
    ...input,
    scope: {
      ...a.scope,
      platformSessionId: 99
    }
  }));
  duplicate = true;
  await assert.rejects(saved.read(input));
  duplicate = false;
  revoked = true;
  await assert.rejects(saved.read(input), /retired authority/);
  assert.equal(minted, 0);
});
test('actual multipart upload route returns a closed public projection and retains graph provenance privately', async () => {
  const {
      Readable
    } = require('node:stream'),
    {
      EventEmitter
    } = require('node:events');
  const boundary = 'v06-controlled-boundary',
    parts = [];
  for (const [name, value] of Object.entries({
    sessionId: id(51),
    requestId: id(52),
    message: 'Upload attached avatar',
    public: 'false'
  })) parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
  parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="lesson.html"\r\nContent-Type: text/html\r\n\r\nlesson\r\n--${boundary}--\r\n`);
  const bytes = Buffer.from(parts.join('')),
    req = Object.assign(Readable.from([bytes]), {
      headers: {
        'content-type': `multipart/form-data; boundary=${boundary}`,
        'content-length': String(bytes.length)
      },
      ssLaunch: {},
      ssUser: {
        id: 11,
        role: 'customer'
      },
      ssPersonaSession: {
        sessionId: id(12),
        authorityVersion: '1'
      },
      query: {}
    });
  const privateResult = {
    text: 'Stored attachment.',
    replayed: false,
    hops: [{
      private: 'trace'
    }],
    taskMetadata: {
      boundUpload: {
        operationId: id(1),
        uploadRequestId: id(52),
        outcome: 'completed',
        originalEnvelope: 'private envelope',
        graphEffect: {
          ownerKey: 'private-owner',
          runId: 'private-run'
        }
      }
    }
  };
  let out;
  const res = Object.assign(new EventEmitter(), {
    status(code) {
      assert.equal(code, 200);
      return this;
    },
    json(value) {
      out = value;
    }
  });
  const router = require('../server/routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
    assessment: {async runAttempt(){throw Error('Unexpected assessment');},async readOutcome(){throw Error('Unexpected assessment');}},
    svgAssessment: unavailableSvgAssessment,
    launches: {
      resolveCapability: async () => {}
    },
    authenticatePersona: (_q, _s, n) => n(),
    graph: {
      createSession: async () => ({}),
      async run(input) {
        assert.equal(input.attachment.bytes.toString(), 'lesson');
        return privateResult;
      }
    },
    saved: {
      read: async () => {},
      asset: async () => {}
    }
  });
  await router.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/run').route.stack.at(-1).handle(req, res);
  assert.deepEqual(Object.keys(out).sort(), ['byteCount', 'filename', 'operationId', 'replayed', 'status', 'text', 'uploadRequestId']);
  assert.equal(JSON.stringify(out).includes('private'), false);
  assert.equal(privateResult.taskMetadata.boundUpload.graphEffect.ownerKey, 'private-owner');
});
test('asset remints preserve first canonical serve and concurrent delivery cannot retire another request lease', async () => {
  const {
    EventEmitter
  } = require('node:events');
  const ids = {
    effectId: id(80),
    operationId: id(1),
    targetId: id(4),
    generation: 1,
    sceneId: id(9),
    sceneGeneration: 1,
    mode: 'vuln',
    modeGeneration: 0,
    modeStamp: 'a'.repeat(64)
  };
  let time = 1700000000000,
    stored = null,
    records = 0,
    releaseRead,
    readGate = null;
  const capability = require('../server/services/secureshopUploadAssetCapability').createSecureShopUploadAssetCapability({
    secret: 'x'.repeat(32),
    now: () => time
  });
  const lookup = async () => ({
    admission: {
      scope: {}
    },
    effect: {
      effectId: ids.effectId
    },
    canonicalServe: stored,
    contentType: 'text/html',
    contentDisposition: 'inline; filename="lesson.html"',
    responseByteCount: 1,
    responseSha256: digest(Buffer.from('x'))
  });
  const service = require('../server/services/secureshopUploadAssetService').createSecureShopUploadAssetService({
    assetHost: '127.0.0.2',
    platformHost: '127.0.0.1',
    port: 9083,
    origin: 'http://127.0.0.2:9083',
    capability,
    lookup,
    read: async () => {
      if (readGate) await readGate;
      return Buffer.from('x');
    },
    assertCurrent: async () => {},
    recordServe: async (_a, receipt) => {
      records++;
      stored = receipt;
    },
    createServer() {}
  });
  const response = () => Object.assign(new EventEmitter(), {
    headers: {},
    setHeader(k, v) {
      this.headers[k] = v;
    },
    end() {
      this.headersSent = true;
      queueMicrotask(() => this.emit('finish'));
    }
  });
  const request = token => ({
    method: 'GET',
    url: token.path,
    headers: {host:'127.0.0.2:9083'}
  });
  const first = capability.mint(ids);
  readGate = new Promise(resolve => {
    releaseRead = resolve;
  });
  const res1 = response(),
    pending = service.handler(request(first), res1);
  await new Promise(resolve => setImmediate(resolve));
  time++;
  const retry = capability.mint(ids),
    res2 = response();
  await service.handler(request(retry), res2);
  assert.equal(res2.statusCode, 404);
  const res3 = response();
  await service.handler(request(retry), res3);
  assert.equal(res3.statusCode, 404);
  assert.equal(records, 0);
  releaseRead();
  readGate = null;
  await pending;
  assert.equal(records, 1);
  assert.equal(stored.receiptPath, first.path);
  time++;
  const second = capability.mint(ids),
    res4 = response();
  await service.handler(request(second), res4);
  assert.equal(res4.statusCode, 200);
  assert.equal(records, 1);
  assert.equal(stored.receiptPath, first.path);
  assert.equal(res4.headers['X-Content-Type-Options'], undefined);
  assert.equal(first.path.includes(ids.targetId), false);
});
test('actual application asset-stop failure still closes agents and database pools exactly once', async () => {
  const {
    readFileSync
  } = require('node:fs');
  const source = readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const start = source.indexOf('const uploadAssets = app.locals.secureshopUploadAssets;');
  assert.ok(start > 0);
  const end = source.indexOf('\n    },', start);
  assert.ok(end > start);
  const body = source.slice(start, end),
    calls = [];
  const lifecycle = require('../server/services/applicationLifecycle');
  const app = {
    locals: {
      secureshopUploadAssets: {
        async stop() {
          calls.push('asset');
          throw Error('retained serve failure');
        }
      },
      secureshopV2: {
        pool: {
          async close() {
            calls.push('agentPool');
          }
        },
        agentHost: {
          async stop() {
            calls.push('agentHost');
          }
        }
      }
    }
  };
  const loaded = name => name === './services/secureshop' ? {
    settleSecureShopCleanup: lifecycle.settleApplicationCleanup
  } : new Proxy({}, {
    get(_target, key) {
      return async () => {
        calls.push(key);
      };
    }
  });
  const run = new (Object.getPrototypeOf(async function () {}).constructor)('app', 'loaded', 'closeApplicationOwnedResources', 'settleApplicationCleanup', 'let ctfAuthorityRouter;\n' + body);
  await assert.rejects(run(app, loaded, lifecycle.closeApplicationOwnedResources, lifecycle.settleApplicationCleanup), AggregateError);
  for (const name of ['asset', 'agentPool', 'agentHost', 'closePostgresPools', 'closeSecureShopReviewDb']) assert.equal(calls.filter(value => value === name).length, 1);
  assert.equal(calls[0], 'asset');
});
test('request-ID recovery route uses authenticated context and saved read only after lost POST acknowledgement', async () => {
  const {
    EventEmitter
  } = require('node:events');
  let input,
    turns = 0,
    mints = 0,
    out;
  const router = require('../server/routes/secureshop/boundAvatarUpload').createBoundAvatarUploadRouter({
    assessment: {async runAttempt(){throw Error('Unexpected assessment');},async readOutcome(){throw Error('Unexpected assessment');}},
    svgAssessment: unavailableSvgAssessment,
    launches: {
      resolveCapability: async () => {}
    },
    authenticatePersona: (_q, _s, n) => n(),
    graph: {
      createSession: async () => {
        turns++;
      },
      run: async () => {
        turns++;
      }
    },
    saved: {
      async read(value) {
        input = value;
        return {
          operationId: id(1),
          uploadRequestId: id(2),
          status: 'uncertain',
          filename: 'lesson.html',
          byteCount: 6
        };
      },
      async asset() {
        mints++;
      }
    }
  });
  const scope = {
    launchId: id(5),
    scenarioId: id(6),
    generation: 1,
    platformOwnerId: 7,
    platformSessionId: 8
  };
  const req = Object.assign(new EventEmitter(), {
    params: {
      requestId: id(2)
    },
    ssLaunch: scope,
    ssUser: {
      id: 11,
      role: 'customer'
    },
    ssPersonaSession: {
      sessionId: id(12),
      authorityVersion: '1'
    },
    query: {},
    body: {}
  });
  const res = Object.assign(new EventEmitter(), {
    status(code) {
      assert.equal(code, 200);
      return this;
    },
    json(value) {
      out = value;
    }
  });
  const handler = router.stack.find(layer => layer.route?.path === '/agents/customer/avatar-upload/requests/:requestId').route.stack.at(-1).handle;
  await handler(req, res);
  assert.equal(input.uploadRequestId, id(2));
  assert.equal(input.operationId, undefined);
  assert.equal(input.scope, scope);
  assert.deepEqual(input.persona, {
    id: 11,
    role: 'customer'
  });
  assert.equal(out.operationId, id(1));
  assert.equal(turns, 0);
  assert.equal(mints, 0);
});

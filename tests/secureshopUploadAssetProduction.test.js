'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  {
    EventEmitter
  } = require('node:events');
const {
  activationPolicy,
  startSecureShopUploadAssetProduction
} = require('../server/services/secureshopUploadAssetProduction');
test('activation requires exact distinct host, public origin, and private secret', () => {
  assert.deepEqual(activationPolicy({}), {
    enabled: false,
    origin: null,
    capability: null
  });
  const base = {
    SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true',
    SS_UPLOAD_ASSET_HOST: '127.0.0.2',
    SS_PLATFORM_HOST: '127.0.0.1',
    SS_UPLOAD_ASSET_PORT: '9083',
    SS_UPLOAD_ASSET_PUBLIC_ORIGIN: 'http://127.0.0.2:9083',
    SS_UPLOAD_ASSET_CAPABILITY_SECRET: 'x'.repeat(32)
  };
  assert.equal(activationPolicy(base).enabled, true);
  const ipv6 = activationPolicy({
    ...base,
    SS_UPLOAD_ASSET_HOST: '::1',
    SS_UPLOAD_ASSET_PUBLIC_ORIGIN: 'http://[::1]:9083'
  });
  assert.equal(ipv6.origin, 'http://[::1]:9083');
  assert.deepEqual(ipv6.platformHosts, ['localhost','127.0.0.1']);
  assert.throws(() => activationPolicy({
    ...base,
    SS_UPLOAD_ASSET_HOST: '127.0.0.1',
    SS_UPLOAD_ASSET_PUBLIC_ORIGIN: 'http://127.0.0.1:9083'
  }));
  assert.throws(() => activationPolicy({
    ...base,
    SS_UPLOAD_ASSET_CAPABILITY_SECRET: 'short'
  }));
  assert.throws(() => activationPolicy({...base,SS_UPLOAD_ASSET_HOST:'::1',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:9083',SS_ALLOWED_ORIGINS:'http://[::1]:3000'}));
  assert.throws(() => activationPolicy({...base,SS_ALLOWED_ORIGINS:'http://localhost:3000/path'}));
});
test('asset listener uses the bound backend and closes exactly once', async () => {
  let listening = 0,
    closed = 0,
    finalizer;
  const server = Object.assign(new EventEmitter(), {
      listen(_p, _h, done) {
        listening++;
        done();
        return this;
      },
      close(done) {
        closed++;
        done();
      }
    }),
    activation = activationPolicy({
      SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true',
      SS_UPLOAD_ASSET_HOST: '127.0.0.2',
      SS_PLATFORM_HOST: '127.0.0.1',
      SS_UPLOAD_ASSET_PORT: '9083',
      SS_UPLOAD_ASSET_PUBLIC_ORIGIN: 'http://127.0.0.2:9083',
      SS_UPLOAD_ASSET_CAPABILITY_SECRET: 'x'.repeat(32)
    }),
    backend = {
      capability: activation.capability,
      lookup: async () => null,
      assertCurrent: async () => {},
      recordServe: async () => {}
    };
  const runtime = await startSecureShopUploadAssetProduction({
    activation,
    backend,
    lifecycle: {
      registerFinalizer(fn) {
        finalizer = fn;
      }
    },
    createServer: () => server,
    reader: async () => Buffer.alloc(0)
  });
  assert.equal(runtime.isReady(), true);
  assert.equal(listening, 1);
  await finalizer();
  await finalizer();
  assert.equal(closed, 1);
  assert.equal(runtime.isReady(), false);
});
test('failed listener start releases ownership and stop remains safe', async () => {
  let closes=0,finalizers=0;
  const error=Object.assign(Error('unavailable'),{code:'EADDRNOTAVAIL'}),server=Object.assign(new EventEmitter(),{
    listen(){queueMicrotask(()=>this.emit('error',error));return this;},
    close(done){closes++;done(Object.assign(Error('not running'),{code:'ERR_SERVER_NOT_RUNNING'}));}
  });
  const activation=activationPolicy({SS_BOUND_UPLOAD_ASSETS_ENABLED:'true',SS_UPLOAD_ASSET_HOST:'::1',SS_UPLOAD_ASSET_PORT:'9083',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:9083',SS_UPLOAD_ASSET_CAPABILITY_SECRET:'x'.repeat(32)}),backend={capability:activation.capability,lookup:async()=>null,assertCurrent:async()=>{},recordServe:async()=>{}};
  await assert.rejects(startSecureShopUploadAssetProduction({activation,backend,lifecycle:{registerFinalizer(){finalizers++;}},createServer:()=>server,reader:async()=>Buffer.alloc(0)}),error);
  assert.equal(closes,1);assert.equal(finalizers,0);
});
test('failed listener start retains unexpected cleanup failure on the bind error', async () => {
  const bindError=Object.assign(Error('unavailable'),{code:'EADDRNOTAVAIL'}),cleanupError=Error('close failed'),server=Object.assign(new EventEmitter(),{
    listen(){queueMicrotask(()=>this.emit('error',bindError));return this;},
    close(done){done(cleanupError);}
  });
  const activation=activationPolicy({SS_BOUND_UPLOAD_ASSETS_ENABLED:'true',SS_UPLOAD_ASSET_HOST:'::1',SS_UPLOAD_ASSET_PORT:'9083',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:9083',SS_UPLOAD_ASSET_CAPABILITY_SECRET:'x'.repeat(32)}),backend={capability:activation.capability,lookup:async()=>null,assertCurrent:async()=>{},recordServe:async()=>{}};
  await assert.rejects(startSecureShopUploadAssetProduction({activation,backend,lifecycle:{registerFinalizer(){throw Error('must not register');}},createServer:()=>server,reader:async()=>Buffer.alloc(0)}),error=>error===bindError&&error.cleanupError===cleanupError);
});
test('asset activation shares the application CORS truthy origin semantics', () => {
  const base={SS_BOUND_UPLOAD_ASSETS_ENABLED:'true',SS_UPLOAD_ASSET_HOST:'::1',SS_UPLOAD_ASSET_PORT:'9083',SS_UPLOAD_ASSET_PUBLIC_ORIGIN:'http://[::1]:9083',SS_UPLOAD_ASSET_CAPABILITY_SECRET:'x'.repeat(32)};
  assert.deepEqual(activationPolicy({...base,SS_ALLOWED_ORIGINS:''}).platformHosts,['localhost','127.0.0.1']);
  assert.throws(()=>activationPolicy({...base,SS_ALLOWED_ORIGINS:'   '}),/Exact SecureShop platform origins required/);
  assert.deepEqual(activationPolicy({...base,SS_ALLOWED_ORIGINS:'http://localhost:3000, http://127.0.0.1:8081'}).platformHosts,['localhost','127.0.0.1']);
});

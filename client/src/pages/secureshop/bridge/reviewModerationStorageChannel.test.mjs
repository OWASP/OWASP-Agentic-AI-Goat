import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { validateShopSnapshot } from './stateStore.mjs';
import { SHOP_TOKEN_KEY, SHOP_CART_KEY, SHOP_REVIEW_MODERATION_KEY } from '../utils/shopStorage.mjs';

test('old empty shop snapshots remain valid with optional moderation reference absent', () => {
  const old = { [SHOP_TOKEN_KEY]: null, [SHOP_CART_KEY]: null };
  expect(validateShopSnapshot(old)).toEqual(old);
  expect(validateShopSnapshot(old)).not.toHaveProperty(SHOP_REVIEW_MODERATION_KEY);
});

test('real parent/frame MessageChannel acknowledges save and omission, then fails closed on rejection and disconnect', () => {
  // Native MessagePort cloning targets Node's realm, not Jest's VM realm.
  // Keep the unmodified channel and strict prototype validator together.
  const moduleUrl = name => pathToFileURL(require.resolve(name)).href;
  const script = `
    import assert from 'node:assert/strict';
    import { MessageChannel } from 'node:worker_threads';
    import { createHostShopStateChannel, connectFrameShopState } from ${JSON.stringify(moduleUrl('./stateChannel.mjs'))};
    import { createScopedShopStateStore } from ${JSON.stringify(moduleUrl('./stateStore.mjs'))};
    import { createShopStorage, SHOP_REVIEW_MODERATION_KEY } from ${JSON.stringify(moduleUrl('../utils/shopStorage.mjs'))};
    import { createReviewModerationReferenceStore } from ${JSON.stringify(moduleUrl('../utils/reviewModerationReference.mjs'))};
    const id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', actionId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const key='c'.repeat(64);
    const lookup=(state,result=null)=>({version:1,requestId:id,requestedLimit:100,
      recoveryScopeKey:key,state,result});
    const rows=new Map(), ports=new MessageChannel();
    const hostStore=createScopedShopStateStore({storage:{getItem:k=>rows.get(k)??null,
      setItem:(k,v)=>rows.set(k,v)},scenarioId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
      generation:1,isCurrent:()=>true});
    const host=createHostShopStateChannel({port:ports.port1,store:hostStore});
    let frame;
    try {
      frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
      const storage=createShopStorage({getStorage:()=>frame});
      const pending=createReviewModerationReferenceStore({storage,flush:()=>frame.flush()});
      assert.equal(frame.getItem(SHOP_REVIEW_MODERATION_KEY),null);
      assert.equal(Object.hasOwn(hostStore.read(),SHOP_REVIEW_MODERATION_KEY),false);
      await pending.reserveInitialPost({actionId,requestId:id},lookup('not_found'),
        {assertCurrent:()=>true});
      assert.deepEqual(JSON.parse(hostStore.read()[SHOP_REVIEW_MODERATION_KEY]).pending,
        {requestId:id,requestedLimit:100});
      const result={ok:true,processed:0,decisions:[],stopReason:'end_turn',
        batch:{requested:100,considered:1,complete:true,continuationRequired:false}};
      await pending.recordCompleted(lookup('completed',result),[],{assertCurrent:()=>true});
      await pending.finish([lookup('completed',result)],{assertCurrent:()=>true});
      assert.equal(frame.getItem(SHOP_REVIEW_MODERATION_KEY),null);
      assert.equal(Object.hasOwn(hostStore.read(),SHOP_REVIEW_MODERATION_KEY),false);
      host.close();
      await new Promise(resolve=>setTimeout(resolve,0));
      assert.throws(()=>frame.getItem(SHOP_REVIEW_MODERATION_KEY));
    } finally {frame?.close();host.close();}
    const rejectedPorts=new MessageChannel();
    const rejectingHost=createHostShopStateChannel({port:rejectedPorts.port1,
      store:{read:()=>({secureshop_v2_token:null,ss_guest_cart:null}),
        replace(){throw Error('no persistence');},close(){}}});
    let rejectedFrame;
    try {
      rejectedFrame=await connectFrameShopState({port:rejectedPorts.port2,timeoutMs:1000});
      const raw=JSON.stringify({version:1,actionId,recoveryScopeKey:key,completed:[],
        pending:{requestId:id,requestedLimit:100}});
      rejectedFrame.setItem(SHOP_REVIEW_MODERATION_KEY,raw);
      await assert.rejects(rejectedFrame.flush());
      assert.throws(()=>rejectedFrame.setItem(SHOP_REVIEW_MODERATION_KEY,raw));
      rejectedFrame.close();
      assert.throws(()=>rejectedFrame.getItem(SHOP_REVIEW_MODERATION_KEY));
    } finally {rejectedFrame?.close();rejectingHost.close();}
  `;
  expect(() => execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    timeout: 5000, encoding: 'utf8', stdio: 'pipe',
  })).not.toThrow();
});

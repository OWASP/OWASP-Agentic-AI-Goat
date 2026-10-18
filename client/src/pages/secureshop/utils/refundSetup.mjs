const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[a-f0-9]{12}$/;

export function decodeRefundSetup(value) {
  if (value === null) return null;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'choiceId,kind,orderId,version'
    || value.version !== 1 || value.kind !== 'refund_setup'
    || typeof value.choiceId !== 'string' || !UUID.test(value.choiceId)
    || !Number.isSafeInteger(value.orderId) || value.orderId < 1 || value.orderId > 2147483647)
    throw Error('Saved refund review is invalid.');
  return Object.freeze({ version: 1, kind: 'refund_setup', choiceId: value.choiceId, orderId: value.orderId });
}

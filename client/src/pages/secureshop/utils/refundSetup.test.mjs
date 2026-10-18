import { decodeRefundSetup } from './refundSetup.mjs';

const setup = { version: 1, kind: 'refund_setup',
  choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 42 };

test('only a closed canonical saved refund handoff is accepted', () => {
  expect(decodeRefundSetup(setup)).toEqual(setup);
  expect(decodeRefundSetup(null)).toBeNull();
  for (const candidate of [
    { ...setup, orderId: 0 }, { ...setup, orderId: 2147483648 },
    { ...setup, choiceId: setup.choiceId.toUpperCase() },
    { ...setup, reason: 'Invented' }, { ...setup, ticketId: 77 },
  ]) expect(() => decodeRefundSetup(candidate)).toThrow('Saved refund review is invalid');
});

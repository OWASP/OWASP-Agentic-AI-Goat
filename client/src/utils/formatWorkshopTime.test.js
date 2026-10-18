import { formatWorkshopTime } from './formatWorkshopTime';

describe('formatWorkshopTime', () => {
  test.each([
    [0, '0s'],
    [1, '1s'],
    [59, '59s'],
    [60, '1m'],
    [3599, '59m'],
    [3600, '1h 0m'],
    [3661, '1h 1m'],
    [null, '0s'],
  ])('formats canonical seconds %p as %s', (seconds, expected) => {
    expect(formatWorkshopTime(seconds)).toBe(expected);
  });
});

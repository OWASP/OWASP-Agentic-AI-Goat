import { decodeCatalogPage } from './catalogPage.mjs';

test('catalog page accepts only closed saved count metadata', () => {
  const page = { version: 1, total: 17, pageSize: 12, returnedCount: 12, hasMore: true };
  expect(decodeCatalogPage(page, 12)).toEqual(page);
  expect(decodeCatalogPage(null, 12)).toBeNull();
  for (const bad of [
    { ...page, cursor: 'private' }, { ...page, pageSize: 5 },
    { ...page, returnedCount: 13 }, { ...page, total: -1 },
    { ...page, hasMore: 'true' }, { ...page, returnedCount: 0 },
    { ...page, total: 12 }, { ...page, returnedCount: 1 },
  ]) expect(() => decodeCatalogPage(bad, 12)).toThrow('Saved catalog page invalid');
});

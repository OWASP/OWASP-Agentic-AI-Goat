import { resolveCsrfDeepLink } from './csrfDeepLink.mjs';

const tab = (id, objectives) => ({ id, objectives });
const objective = (id, payload = true) => ({ id, payload });

test('canonical CSRF deep link selects the visible POST payload objective', () => {
  const result = resolveCsrfDeepLink('?scenario=post&objective=csrf_p1', [
    tab('get', [objective('csrf_g1', false)]),
    tab('post', [objective('csrf_p1'), objective('csrf_p2')]),
  ]);
  expect(result).toEqual({ tabIndex: 1, objectiveId: 'csrf_p1' });
});

test('a hidden objective is never selected or restored by its query parameter', () => {
  const result = resolveCsrfDeepLink('?scenario=post&objective=csrf_p1', [
    tab('get', [objective('csrf_g1', false)]),
    tab('post', [objective('csrf_p2')]),
  ]);
  expect(result).toEqual({ tabIndex: 1, objectiveId: null });
});

test('a hidden exercise cannot be selected through its deep link', () => {
  const result = resolveCsrfDeepLink('?scenario=post&objective=csrf_p1', [
    tab('get', []), tab('post', []),
  ]);
  expect(result).toEqual({ tabIndex: 0, objectiveId: null });
});

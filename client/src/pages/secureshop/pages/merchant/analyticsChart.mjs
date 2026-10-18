// PostgreSQL bigint/numeric values arrive as strings. Plot safe magnitudes while
// leaving the exact original values untouched in the result table.
const preferred = ['revenue', 'total', 'total_amount', 'units_sold', 'count', 'orders'];
function numeric(value) {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value))) return null;
  const result = Number(value);
  return Number.isFinite(result) && Math.abs(result) <= Number.MAX_SAFE_INTEGER ? result : null;
}
export function analyticsChart(rows) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const first = rows[0];
  if (!first || typeof first !== 'object') return null;
  const keys = Object.keys(first);
  const numericKey = preferred.find(key => numeric(first[key]) !== null)
    || keys.find(key => key !== 'id' && typeof first[key] === 'number' && numeric(first[key]) !== null);
  if (!numericKey) return null;
  const labelKey = ['name', 'username', 'status', 'category', 'day'].find(key => key in first);
  const projected = rows.slice(0, 15).map(row => ({
    name: labelKey ? String(row[labelKey] ?? row.id ?? '—') : numericKey,
    revenue: numeric(row[numericKey]),
  }));
  if (projected.some(row => row.revenue === null)) return null;
  return { rows: projected, label: labelKey ? `${numericKey} by ${labelKey}` : numericKey,
    metric: numericKey, kind: labelKey === 'day' ? 'line' : 'bar' };
}

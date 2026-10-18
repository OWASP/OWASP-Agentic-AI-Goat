export function formatWorkshopTime(seconds) {
  const normalizedSeconds = Math.max(0, Math.floor(Number(seconds) || 0));
  if (normalizedSeconds < 60) return `${normalizedSeconds}s`;
  const hours = Math.floor(normalizedSeconds / 3600);
  const minutes = Math.floor((normalizedSeconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

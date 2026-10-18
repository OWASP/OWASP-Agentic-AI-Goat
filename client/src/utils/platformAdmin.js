// Presentation policy mirrors canonical PostgreSQL role AND level checks.
// This does not replace server-side authorization or durable session validation.
export function hasPlatformAdminLevel(user, level = 1) {
  return Boolean(user && ['admin', 'super_admin'].includes(user.role)
    && (user.adminLevel ?? user.admin_level ?? 0) >= level);
}

export function projectPlatformUser(user) {
  if (!user) return user;
  const isAdmin = hasPlatformAdminLevel(user);
  return { ...user, isAdmin, isWorkshopAdmin: isAdmin };
}

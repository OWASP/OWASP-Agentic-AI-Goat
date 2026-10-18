-- Repair fresh-install administrators without reactivating revoked or expired grants.
-- Ordinary administrators remain explicitly provisioned; database_access is not
-- part of the established default administrator permission set.
INSERT INTO identity.admin_permissions(admin_id,permission_name,granted_by)
SELECT u.id,p.permission,u.id
FROM identity.users u
CROSS JOIN unnest(ARRAY['user_management','challenge_management','system_config',
 'view_analytics','manage_progress','send_notifications','export_data','system_logs']) AS p(permission)
WHERE u.role='super_admin' AND u.admin_level=2 AND u.is_active=1
ON CONFLICT(admin_id,permission_name) DO NOTHING;

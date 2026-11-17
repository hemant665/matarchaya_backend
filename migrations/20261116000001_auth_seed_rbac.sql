-- Baseline RBAC data. Idempotent so it is safe to re-run in a fresh database.
--
-- Roles match the frontend's RoleEnum ("User", "Admin"); the API returns the
-- stored lowercase name and the frontend normalizes it.
-- Permissions are what routes are guarded with, e.g.
-- `check_permission_middleware(req, next, "admin")`.

INSERT INTO roles (name, description) VALUES
    ('admin', 'Administrator with access to the admin portal'),
    ('user',  'Registered user')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    ('admin', 'Access to admin-only endpoints'),
    ('user',  'Access to endpoints for any signed-in user')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM (VALUES
    ('admin', 'admin'),
    ('admin', 'user'),
    ('user',  'user')
) AS grants(role_name, permission_name)
JOIN roles r        ON r.name = grants.role_name
JOIN permissions p  ON p.name = grants.permission_name
ON CONFLICT DO NOTHING;
